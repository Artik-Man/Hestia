//go:build linux

package awg

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	installedStorePath = "/etc/hestia/awg"
	readyMarkerPath    = "/run/hestia-awg/ready"
	healthMarkerPath   = "/run/hestia-awg/health.json"
	routeManifestPath  = "/run/hestia-awg/routes.json"
)

// ServeReadyConnector keeps the requested ready userspace connector active until its service context ends.
func (InstalledRuntime) ServeReadyConnector(ctx context.Context, id string) (returnErr error) {
	store := &Store{directory: installedStorePath}
	var ids []string
	if id != "" {
		ids = []string{id}
	}
	metadata, raw, err := store.LoadReadyForRuntime(ids...)
	if err != nil {
		return err
	}
	policy, err := newSlotRoutePolicy(ExecRouteRunner{}, metadata.Slot)
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
	_ = os.Remove(readyPath)
	_ = os.Remove(healthPath)
	expected := policy.manifest(metadata.ID)
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
	configDir, err := os.MkdirTemp("/run/hestia-awg", "active-")
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
		guard := outerPolicy(metadata.Slot)
		if err := guard.outerBarrier(ctx, metadata.ID, true); err != nil {
			return err
		}
		runtimeConfig = relay.runtimeSettings(runtimeConfig, guard.mark)
	}
	if err := os.WriteFile(configPath, runtimeConfig, 0600); err != nil {
		return errors.New("cannot stage private runtime configuration")
	}
	if err := runAWG(ctx, awgToolPath, "setconf", policy.device, configPath); err != nil {
		return errors.New("userspace runtime rejected the stored profile")
	}
	if err := runAWG(ctx, ipToolPath, "addr", "add", metadata.IPv4Address, "dev", policy.device, "noprefixroute"); err != nil {
		return errors.New("cannot configure the AWG IPv4 address")
	}
	if err := runAWG(ctx, ipToolPath, "link", "set", "dev", policy.device, "up"); err != nil {
		return errors.New("cannot activate the AWG interface")
	}
	if relay != nil {
		port, err := runProcess(awgToolPath, "show", policy.device, "listen-port")
		if err != nil {
			return errors.New("cannot inspect WireGuard transport socket")
		}
		if err := relay.attach(ctx, policy.device, peerSetting(profile.RuntimeConfig, "PublicKey"), port); err != nil {
			return err
		}
		return policy.superviseManualTransport(ctx, relay, metadata, readyPath, healthPath)
	}
	if err := initiateHandshake(ctx, policy.device, profile.RuntimeConfig, runProcess); err != nil {
		return err
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		return err
	}
	if err := policy.probeMarkedEgress(ctx, metadata.DNSIPv4); err != nil {
		return err
	}
	if err := writeHealthMarker(healthPath, metadata.ID); err != nil {
		return err
	}
	if err := writeReadyMarker(readyPath); err != nil {
		return err
	}
	defer os.Remove(readyPath)
	healthTicker := time.NewTicker(time.Second)
	defer healthTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-healthTicker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := policy.probeMarkedEgress(probeCtx, metadata.DNSIPv4)
			cancel()
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				_ = os.Remove(healthPath)
				return errors.New("AWG runtime health probe failed")
			}
			if err := writeHealthMarker(healthPath, metadata.ID); err != nil {
				return err
			}
		}
	}
}

// hestiaOutboundDisabled confirms sing-box is stopped before route teardown can remove fail-closed guards.
func hestiaOutboundDisabled(ctx context.Context) error {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "hestia-sing-box.service")
	if err := command.Run(); err == nil {
		return errors.New("Hestia outbound is still active")
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 3 {
			return errors.New("cannot confirm Hestia outbound is stopped")
		}
	}
	return nil
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
	group, err := user.LookupGroup("hestia-snapshot")
	if err != nil {
		return errors.New("cannot resolve Hestia snapshot group")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return errors.New("cannot resolve Hestia snapshot group")
	}
	return writeHealthRecord(path, id, 0, gid, time.Now().UTC(), active...)
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
	stat, ok := info.Sys().(*syscall.Stat_t)
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
	return &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = errors.Join(
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, p.markValue),
					syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, p.device),
				)
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
}

// probeMarkedEgress resolves ya.ru through the profile DNS server and fetches HTTPS using the same mark/interface path.
func (p RoutePolicy) probeMarkedEgress(ctx context.Context, dnsServer string) error {
	dialer := p.boundDialer()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(dnsServer, "53"))
		},
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, candidate := range addresses {
				if candidate.IP.To4() == nil {
					continue
				}
				connection, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(candidate.IP.String(), port))
				if err == nil {
					return connection, nil
				}
			}
			return nil, errors.New("no IPv4 HTTPS endpoint was reachable")
		},
	}
	defer transport.CloseIdleConnections()
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "https://ya.ru/", nil)
	if err != nil {
		return errors.New("cannot prepare bound HTTPS probe")
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return errors.New("AWG-bound DNS and HTTPS probe failed")
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
	policy, err := newSlotRoutePolicy(ExecRouteRunner{}, slot)
	if err != nil {
		return err
	}
	path := routeManifestPath
	if !legacy {
		path += "." + id
	}
	expected := policy.manifest(id)
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
		if err := outerPolicy(slot).outerBarrier(ctx, id, false); err != nil {
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
	policy, err := newSlotRoutePolicy(ExecRouteRunner{}, slot)
	if err != nil {
		return err
	}
	exists, err := loadRouteManifest(routeManifestPath+"."+id, policy.manifest(id))
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("AWG route ownership record is missing")
	}
	return policy.verifyReadyPolicy(ctx)
}
