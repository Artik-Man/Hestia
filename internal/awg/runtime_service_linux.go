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
	activeInterface    = "awg0"
)

// ServeReadyConnector keeps the single ready userspace connector active until its service context ends.
func (InstalledRuntime) ServeReadyConnector(ctx context.Context) (returnErr error) {
	store := &Store{directory: installedStorePath}
	metadata, raw, err := store.LoadReadyForRuntime()
	if err != nil {
		return err
	}
	profile, err := Parse(raw)
	if err != nil {
		return errors.New("ready AWG profile failed validation")
	}
	if err := os.MkdirAll(filepath.Dir(readyMarkerPath), 0700); err != nil {
		return errors.New("AWG runtime state directory is unavailable")
	}
	_ = os.Remove(readyMarkerPath)
	_ = os.Remove(healthMarkerPath)
	runner := installedRouteRunner{}
	policy := NewRoutePolicy(runner)
	manifest, exists, err := loadRouteManifest(metadata.ID)
	if err != nil {
		return err
	}
	if exists {
		if err := policy.AdoptOwnedState(ctx); err != nil {
			return err
		}
		deleteActiveInterface()
		if err := ensureInterfaceAbsent(ctx, activeInterface); err != nil {
			return err
		}
	} else {
		if err := policy.Preflight(ctx); err != nil {
			return err
		}
		manifest = routeManifest{ID: metadata.ID, Mark: policyMark, Table: policyTable, Priority: policyPriority, Device: activeInterface}
		if err := writeRouteManifest(routeManifestPath, manifest); err != nil {
			return err
		}
	}
	var stopProcess func()
	defer deleteActiveInterface()
	defer os.Remove(healthMarkerPath)
	defer func() {
		if stopProcess != nil {
			stopProcess()
		}
	}()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := policy.Teardown(cleanup, hestiaOutboundDisabled); err != nil {
			if returnErr == nil {
				returnErr = err
			}
			return
		}
		if err := removeRouteManifest(); err != nil && returnErr == nil {
			returnErr = err
		}
	}()
	if err := policy.EnsureGuards(ctx); err != nil {
		return err
	}
	if err := policy.InstallMarkRules(ctx); err != nil {
		return err
	}
	runProcess, stop, err := startUserspace(ctx, activeInterface)
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
	if err := os.WriteFile(configPath, profile.RuntimeConfig, 0600); err != nil {
		return errors.New("cannot stage private runtime configuration")
	}
	if err := runAWG(ctx, awgToolPath, "setconf", activeInterface, configPath); err != nil {
		return errors.New("userspace runtime rejected the stored profile")
	}
	if err := runAWG(ctx, ipToolPath, "addr", "add", metadata.IPv4Address, "dev", activeInterface); err != nil {
		return errors.New("cannot configure the AWG IPv4 address")
	}
	if err := runAWG(ctx, ipToolPath, "link", "set", "dev", activeInterface, "up"); err != nil {
		return errors.New("cannot activate the AWG interface")
	}
	if err := waitHandshake(ctx, activeInterface, runProcess); err != nil {
		return err
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		return err
	}
	if err := probeMarkedEgress(ctx, metadata.DNSIPv4); err != nil {
		return err
	}
	if err := writeHealthMarker(metadata.ID); err != nil {
		return err
	}
	if err := writeReadyMarker(); err != nil {
		return err
	}
	defer os.Remove(readyMarkerPath)
	healthTicker := time.NewTicker(time.Second)
	defer healthTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-healthTicker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
			err := probeMarkedEgress(probeCtx, metadata.DNSIPv4)
			cancel()
			if err != nil {
				_ = os.Remove(healthMarkerPath)
				return errors.New("AWG runtime health probe failed")
			}
			if err := writeHealthMarker(metadata.ID); err != nil {
				return err
			}
		}
	}
}

// installedRouteRunner executes only the fixed iproute2 binary with structured arguments.
type installedRouteRunner struct{}

// Run executes one fixed routing command and returns its bounded output for route ownership checks.
func (installedRouteRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, ipToolPath, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := command.Output()
	if err != nil {
		return nil, errors.New("iproute2 command failed")
	}
	return output, nil
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

// deleteActiveInterface removes only the fixed AWG interface after its userspace process has stopped.
func deleteActiveInterface() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = runAWG(ctx, ipToolPath, "link", "delete", "dev", activeInterface)
}

// writeReadyMarker publishes a root-only signal only after handshake, IPv4 route, DNS, and HTTPS probes pass.
func writeReadyMarker() error {
	file, err := os.OpenFile(readyMarkerPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("cannot publish AWG runtime readiness")
	}
	if _, err := io.WriteString(file, "ready\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(readyMarkerPath)
		return errors.New("cannot publish AWG runtime readiness")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(readyMarkerPath)
		return errors.New("cannot publish AWG runtime readiness")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(readyMarkerPath)
		return errors.New("cannot publish AWG runtime readiness")
	}
	return nil
}

// writeHealthMarker atomically publishes non-secret connector identity and probe time for the group watcher.
func writeHealthMarker(id string) error {
	group, err := user.LookupGroup("hestia-snapshot")
	if err != nil {
		return errors.New("cannot resolve Hestia snapshot group")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return errors.New("cannot resolve Hestia snapshot group")
	}
	return writeHealthRecord(healthMarkerPath, id, 0, gid, time.Now().UTC())
}

// loadRouteManifest validates one root-private record before startup adopts exact AWG policy state left after a crash.
func loadRouteManifest(id string) (routeManifest, bool, error) {
	var manifest routeManifest
	info, err := os.Lstat(routeManifestPath)
	if errors.Is(err, os.ErrNotExist) {
		return manifest, false, nil
	}
	if err != nil || info == nil {
		return manifest, false, errors.New("AWG route ownership record is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != 0 || stat.Nlink != 1 {
		return manifest, false, errors.New("AWG route ownership record is unsafe")
	}
	data, err := os.ReadFile(routeManifestPath)
	if err != nil {
		return manifest, false, errors.New("AWG route ownership record is unreadable")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || manifest.ID != id || manifest.Mark != policyMark || manifest.Table != policyTable || manifest.Priority != policyPriority || manifest.Device != activeInterface {
		return routeManifest{}, false, errors.New("AWG route ownership record does not match the committed connector")
	}
	return manifest, true, nil
}

// removeRouteManifest removes ownership metadata only after route policy teardown has fully succeeded.
func removeRouteManifest() error {
	if err := os.Remove(routeManifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot retire AWG route ownership record")
	}
	return syncDirectory(filepath.Dir(routeManifestPath))
}

// probeMarkedEgress resolves ya.ru through the profile DNS server and fetches HTTPS using the same mark/interface path.
func probeMarkedEgress(ctx context.Context, dnsServer string) error {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			if err := raw.Control(func(fd uintptr) {
				socketErr = errors.Join(
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, 0x202),
					syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, activeInterface),
				)
			}); err != nil {
				return err
			}
			return socketErr
		},
	}
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
