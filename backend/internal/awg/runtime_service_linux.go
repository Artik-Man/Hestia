//go:build linux

package awg

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"github.com/Artik-Man/Hestia/internal/network/socket"
	"github.com/Artik-Man/Hestia/internal/storage"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	installedStorePath = storage.Installed().AWGStore
	readyMarkerPath    = storage.Installed().AWGReady
	healthMarkerPath   = storage.Installed().AWGHealth
	routeManifestPath  = storage.Installed().AWGRoutes
)

// ServeReadyConnector keeps the requested ready userspace connector active until its service context ends.
func (InstalledRuntime) ServeReadyConnector(ctx context.Context, id string) (returnErr error) {
	if err := awgruntime.RequireSupported(runtimeDriver); err != nil {
		return err
	}
	store := &Store{directory: installedStorePath}
	var ids []string
	if id != "" {
		ids = []string{id}
	}
	metadata, raw, err := store.LoadReadyForRuntime(ids...)
	if err != nil {
		return err
	}
	policy, err := newSlotRoutePolicy(routeRunner, metadata.Slot)
	if err != nil {
		return err
	}
	readyPath, healthPath, manifestPath := readyMarkerPath, healthMarkerPath, routeManifestPath
	if id != "" {
		readyPath += "." + id
		healthPath += "." + id
		manifestPath += "." + id
	}
	profile, err := Parse(raw)
	if err != nil {
		return errors.New("ready AWG profile failed validation")
	}
	if err := os.MkdirAll(filepath.Dir(readyPath), 0700); err != nil {
		return errors.New("AWG runtime state directory is unavailable")
	}
	dnsServers := profileDNSIPv4(profile.DNS)
	_ = os.Remove(readyPath)
	_ = os.Remove(healthPath)
	expected := policy.manifest(metadata.ID)
	if err := migrateLegacyRouteManifest(ctx, manifestPath, expected, 1002+metadata.Slot); err != nil {
		return err
	}
	exists, err := loadRouteManifest(manifestPath, expected)
	if err != nil {
		return err
	}
	if exists {
		if err := policy.AdoptOwnedState(ctx); err != nil {
			return err
		}
		if err := ensureInterfaceAbsent(ctx, policy.device); err != nil {
			return err
		}
	} else {
		if err := policy.Preflight(ctx); err != nil {
			return err
		}
		if err := writeRouteManifest(manifestPath, expected); err != nil {
			return err
		}
	}
	var stopProcess func()
	defer os.Remove(healthPath)
	defer func() {
		if stopProcess != nil {
			stopProcess()
		}
	}()
	defer func() {
		// Named units keep guards until binding has drained and explicitly retired this slot.
		if id != "" {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := policy.Teardown(cleanup, hestiaOutboundDisabled); err != nil {
			if returnErr == nil {
				returnErr = err
			}
			return
		}
		if err := removeRouteManifest(manifestPath); err != nil && returnErr == nil {
			returnErr = err
		}
	}()
	if err := policy.EnsureGuards(ctx); err != nil {
		return err
	}
	if err := policy.InstallMarkRules(ctx); err != nil {
		return err
	}
	runProcess, stop, err := startUserspace(ctx, policy.device)
	if err != nil {
		return err
	}
	stopProcess = stop
	configDir, err := os.MkdirTemp(storage.Installed().AWGRuntime, "active-")
	if err != nil {
		return errors.New("cannot create private runtime configuration")
	}
	defer os.RemoveAll(configDir)
	configPath := filepath.Join(configDir, "profile.conf")
	runtimeConfig := profile.RuntimeConfig
	var relay *underlayRelay
	if len(metadata.Underlays) > 0 {
		relay, err = newUnderlayRelay(metadata.Slot)
		if err != nil {
			return err
		}
		defer relay.close()
		guard, err := outerPolicy(metadata.Slot)
		if err != nil {
			return err
		}
		if err := guard.outerBarrier(ctx, metadata.ID, true); err != nil {
			return err
		}
		runtimeConfig = relay.runtimeSettings(runtimeConfig, guard.mark)
	}
	if err := os.WriteFile(configPath, runtimeConfig, 0600); err != nil {
		return errors.New("cannot stage private runtime configuration")
	}
	if err := runtimeDriver.Configure(ctx, policy.device, configPath); err != nil {
		return errors.New("userspace runtime rejected the stored profile")
	}
	if err := runtimeDriver.Address(ctx, policy.device, metadata.IPv4Address); err != nil {
		return errors.New("cannot configure the AWG IPv4 address")
	}
	if err := runtimeDriver.Activate(ctx, policy.device); err != nil {
		return errors.New("cannot activate the AWG interface")
	}
	if relay != nil {
		port, err := runProcess(awgruntime.ListenPort, policy.device)
		if err != nil {
			return errors.New("cannot inspect WireGuard transport socket")
		}
		if err := relay.attach(ctx, policy.device, peerSetting(profile.RuntimeConfig, "PublicKey"), port); err != nil {
			return err
		}
		return policy.superviseManualTransport(ctx, relay, metadata, dnsServers, readyPath, healthPath)
	}
	if err := initiateHandshake(ctx, policy.device, profile.RuntimeConfig, runProcess); err != nil {
		return err
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		return err
	}
	lastProbeTarget, err := policy.probeMarkedEgress(ctx, dnsServers)
	if err != nil {
		return err
	}
	if err := writeHealthMarker(healthPath, metadata.ID); err != nil {
		return err
	}
	if err := writeReadyMarker(readyPath); err != nil {
		return err
	}
	healthProbeHealthy := true
	defer os.Remove(readyPath)
	healthTicker := time.NewTicker(15 * time.Second)
	defer healthTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-healthTicker.C:
			transferBefore, _ := runProcess(awgruntime.Transfer, policy.device)
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			probeTarget, err := policy.probeMarkedEgress(probeCtx, dnsServers)
			if ctx.Err() != nil {
				cancel()
				return nil
			}
			if err != nil {
				httpsCtx, httpsCancel := context.WithTimeout(ctx, 8*time.Second)
				httpsErr := policy.probeMarkedHTTPS(httpsCtx, policy.boundDialer(), "ya.ru", lastProbeTarget)
				httpsCancel()
				cancel()
				if ctx.Err() != nil {
					return nil
				}
				healthProbeHealthy = false
				log.Printf("%v", classifyHealthProbeFailure(err, httpsErr, runProcess, policy.device, transferBefore))
				continue
			}
			cancel()
			lastProbeTarget = probeTarget
			if !healthProbeHealthy {
				healthProbeHealthy = true
				log.Printf("AWG runtime egress probe recovered")
			}
			if err := writeHealthMarker(healthPath, metadata.ID); err != nil {
				return err
			}
		}
	}
}

// classifyHealthProbeError keeps periodic probe diagnostics useful without exposing network or profile data.
func classifyHealthProbeError(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "DNS probe failed"):
		return errors.New("AWG runtime health probe failed: DNS")
	case strings.Contains(err.Error(), "HTTPS probe failed"):
		return errors.New("AWG runtime health probe failed: HTTPS")
	case strings.Contains(err.Error(), "unexpected status"):
		return errors.New("AWG runtime health probe failed: HTTPS status")
	default:
		return errors.New("AWG runtime health probe failed")
	}
}

// classifyHealthProbeFailure appends only coarse handshake and transfer diagnostics to a sanitized probe category.
func classifyHealthProbeFailure(err, httpsErr error, run awgruntime.Reader, device string, transferBefore []byte) error {
	category := classifyHealthProbeError(err)
	handshakeState := "unknown"
	if data, readErr := run(awgruntime.LatestHandshakes, device); readErr == nil {
		handshakeState = classifyHandshakeFreshness(data, time.Now())
	}
	transferState := "unknown"
	if data, readErr := run(awgruntime.Transfer, device); readErr == nil {
		transferState = classifyTransferChange(transferBefore, data)
	}
	httpsState := "passed"
	if httpsErr != nil {
		httpsState = "failed"
	}
	return errors.New(category.Error() + " (handshake=" + handshakeState + ", transfer=" + transferState + ", separate-https=" + httpsState + ")")
}

// classifyHandshakeFreshness reports only whether an AWG handshake timestamp is recent, stale or absent.
func classifyHandshakeFreshness(data []byte, now time.Time) string {
	var latest int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		stamp, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		if stamp > latest {
			latest = stamp
		}
	}
	if latest == 0 {
		return "missing"
	}
	age := now.Sub(time.Unix(latest, 0))
	if age >= 0 && age <= 3*time.Minute {
		return "recent"
	}
	return "stale"
}

// classifyTransferChange compares aggregate byte counters while discarding peer identifiers and exact traffic volume.
func classifyTransferChange(before, after []byte) string {
	beforeRX, beforeTX, beforeOK := transferTotals(before)
	afterRX, afterTX, afterOK := transferTotals(after)
	if !beforeOK || !afterOK {
		return "unknown"
	}
	rxChanged, txChanged := beforeRX != afterRX, beforeTX != afterTX
	switch {
	case rxChanged && txChanged:
		return "rx-tx-changed"
	case rxChanged:
		return "rx-changed"
	case txChanged:
		return "tx-changed"
	}
	return "unchanged"
}

// transferTotals parses only RX/TX byte counters from awg show transfer output and discards peer keys.
func transferTotals(data []byte) (uint64, uint64, bool) {
	var rxTotal, txTotal uint64
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		rx, rxErr := strconv.ParseUint(fields[1], 10, 64)
		tx, txErr := strconv.ParseUint(fields[2], 10, 64)
		if rxErr != nil || txErr != nil || ^uint64(0)-rxTotal < rx || ^uint64(0)-txTotal < tx {
			return 0, 0, false
		}
		seen = true
		rxTotal += rx
		txTotal += tx
	}
	return rxTotal, txTotal, seen
}

// hestiaOutboundDisabled confirms sing-box is stopped before route teardown can remove fail-closed guards.
func hestiaOutboundDisabled(ctx context.Context) error {
	return offlineVerifier.OutboundDisabled(ctx)
}

// writeReadyMarker publishes a root-only signal only after handshake, IPv4 route, DNS, and HTTPS probes pass.
func writeReadyMarker(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot publish AWG runtime readiness")
	}
	if _, err := io.WriteString(file, "ready\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("cannot publish AWG runtime readiness")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("cannot publish AWG runtime readiness")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("cannot publish AWG runtime readiness")
	}
	return nil
}

// writeHealthMarker atomically publishes non-secret connector identity and probe time for the group watcher.
func writeHealthMarker(path, id string, active ...string) error {
	uid, gid, mode, err := healthMarkerOwnership()
	if err != nil {
		return err
	}
	return writeHealthRecord(path, id, uid, gid, mode, time.Now().UTC(), active...)
}

// loadRouteManifest validates one root-private record before startup adopts exact AWG policy state left after a crash.
func loadRouteManifest(path string, expected routeManifest) (bool, error) {
	var manifest routeManifest
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info == nil {
		return false, errors.New("AWG route ownership record is unsafe")
	}
	stat, ok := storage.Stat(info)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != 0 || stat.Nlink != 1 {
		return false, errors.New("AWG route ownership record is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, errors.New("AWG route ownership record is unreadable")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || manifest != expected {
		return false, errors.New("AWG route ownership record does not match the committed connector")
	}
	return true, nil
}

// removeRouteManifest removes ownership metadata only after route policy teardown has fully succeeded.
func removeRouteManifest(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot retire AWG route ownership record")
	}
	return syncDirectory(filepath.Dir(path))
}

// boundDialer confines connections to this tunnel's policy mark and interface.
func (p RoutePolicy) boundDialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, Control: socket.Platform{}.Bind(socket.Path{Device: p.device, Mark: p.markValue, Mode: socket.MarkAndDevice})}
}

// profileDNSIPv4 returns the profile's IPv4 DNS servers in configured order without duplicates.
func profileDNSIPv4(servers []netip.Addr) []string {
	result := make([]string, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if !server.IsValid() || !server.Is4() {
			continue
		}
		address := server.String()
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result
}

// probeMarkedEgress resolves ya.ru and checks HTTPS through the first configured IPv4 resolver that succeeds.
func (p RoutePolicy) probeMarkedEgress(ctx context.Context, dnsServers []string) (netip.Addr, error) {
	if len(dnsServers) == 0 {
		return netip.Addr{}, errors.New("AWG-bound DNS probe has no IPv4 resolver")
	}
	dialer := p.boundDialer()
	var lastErr error
	for index, dnsServer := range dnsServers {
		address, err := p.probeMarkedEgressViaDNS(ctx, dialer, dnsServer)
		if err != nil {
			lastErr = err
			continue
		}
		if index > 0 {
			log.Printf("AWG egress probe passed using configured DNS resolver %d after earlier resolver failure", index+1)
		}
		return address, nil
	}
	return netip.Addr{}, lastErr
}

// probeMarkedEgressViaDNS tests one resolver and bound HTTPS while returning only the resolved IPv4 address for in-memory diagnostics.
func (p RoutePolicy) probeMarkedEgressViaDNS(ctx context.Context, dialer *net.Dialer, dnsServer string) (netip.Addr, error) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, net.JoinHostPort(dnsServer, "53"))
	}}
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	addresses, err := resolver.LookupNetIP(probeCtx, "ip4", "ya.ru")
	if err != nil {
		return netip.Addr{}, errors.New("AWG-bound DNS probe failed")
	}
	for _, address := range addresses {
		if err := p.probeMarkedHTTPS(probeCtx, dialer, "ya.ru", address); err == nil {
			return address, nil
		}
	}
	return netip.Addr{}, errors.New("AWG-bound HTTPS probe failed")
}

// probeMarkedHTTPS performs an HTTPS request to a known IPv4 address without relying on DNS.
func (p RoutePolicy) probeMarkedHTTPS(ctx context.Context, dialer *net.Dialer, host string, address netip.Addr) error {
	if !address.IsValid() || !address.Is4() {
		return errors.New("AWG-bound HTTPS probe has no known IPv4 target")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, endpoint string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				return nil, errors.New("invalid HTTPS probe endpoint")
			}
			return dialer.DialContext(ctx, "tcp4", net.JoinHostPort(address.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	if err != nil {
		return errors.New("cannot prepare bound HTTPS probe")
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return errors.New("AWG-bound HTTPS probe failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return errors.New("AWG-bound HTTPS probe returned an unexpected status")
	}
	return nil
}

// RetireStoppedConnector removes residual guarded policy for a stopped instance only after checking ownership and outbound drain.
func RetireStoppedConnector(ctx context.Context, id string, slot int, legacy bool) error {
	if !ValidConnectionID(id) {
		return errors.New("invalid AWG runtime identity")
	}
	policy, err := newSlotRoutePolicy(routeRunner, slot)
	if err != nil {
		return err
	}
	path := routeManifestPath
	if !legacy {
		path += "." + id
	}
	expected := policy.manifest(id)
	if err := migrateLegacyRouteManifest(ctx, path, expected, 1002+slot); err != nil {
		return err
	}
	exists, err := loadRouteManifest(path, expected)
	if err != nil || !exists {
		return err
	}
	if err := ensureInterfaceAbsent(ctx, policy.device); err != nil {
		return err
	}
	if err := policy.Teardown(ctx, hestiaOutboundDisabled); err != nil {
		return err
	}
	if !legacy {
		guard, err := outerPolicy(slot)
		if err != nil {
			return err
		}
		if err := guard.outerBarrier(ctx, id, false); err != nil {
			return err
		}
	}
	return removeRouteManifest(path)
}

// manifest returns the exact policy tuple which a root-private record must attest for this connector.
func (p RoutePolicy) manifest(id string) routeManifest {
	return routeManifest{ID: id, Mark: p.mark, Table: p.table, Priority: p.priority, Device: p.device}
}

// ConfirmConnectorGuards proves a named unit can be stopped while its outbound stays configured, without changing any route.
func ConfirmConnectorGuards(ctx context.Context, id string, slot int) error {
	if !ValidConnectionID(id) {
		return errors.New("invalid AWG runtime identity")
	}
	policy, err := newSlotRoutePolicy(routeRunner, slot)
	if err != nil {
		return err
	}
	path := routeManifestPath + "." + id
	expected := policy.manifest(id)
	if err := migrateLegacyRouteManifest(ctx, path, expected, 1002+slot); err != nil {
		return err
	}
	exists, err := loadRouteManifest(path, expected)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("AWG route ownership record is missing")
	}
	return policy.verifyReadyPolicy(ctx)
}
