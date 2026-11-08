//go:build linux

package awg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"github.com/Artik-Man/Hestia/internal/storage"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// InstalledRuntime checks a candidate with the pinned userspace daemon without assigning addresses or routes.
type InstalledRuntime struct{}

// Check starts a temporary TUN, applies UAPI-only settings, waits for a peer handshake, and always removes the interface.
func (InstalledRuntime) Check(parent context.Context, profile Profile) error {
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	name, err := temporaryInterfaceName()
	if err != nil {
		return errors.New("cannot allocate temporary AmneziaWG interface")
	}
	if err := ensureInterfaceAbsent(ctx, name); err != nil {
		return err
	}
	runProcess, stopProcess, err := startUserspace(ctx, name)
	if err != nil {
		return err
	}
	defer deleteTemporaryInterface(name)
	defer stopProcess()
	configDir, err := os.MkdirTemp(storage.Installed().AWGRuntime, "check-")
	if err != nil {
		return errors.New("cannot create private temporary runtime directory")
	}
	defer os.RemoveAll(configDir)
	configPath := filepath.Join(configDir, "profile.conf")
	if err := os.WriteFile(configPath, profile.RuntimeConfig, 0600); err != nil {
		return errors.New("cannot stage temporary AmneziaWG settings")
	}
	if err := runtimeDriver.Configure(ctx, name, configPath); err != nil {
		return errors.New("userspace runtime rejected the AmneziaWG profile")
	}
	if err := runtimeDriver.Activate(ctx, name); err != nil {
		return errors.New("cannot activate temporary AmneziaWG interface")
	}
	if err := runtimeDriver.Keepalive(ctx, name, peerSetting(profile.RuntimeConfig, "PublicKey"), "1"); err != nil {
		return errors.New("cannot start temporary AmneziaWG handshake")
	}
	if err := waitHandshake(ctx, name, runProcess); err != nil {
		return err
	}
	return nil
}

// temporaryInterfaceName returns a random Linux interface name within the IFNAMSIZ limit.
func temporaryInterfaceName() (string, error) {
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "hchk" + hex.EncodeToString(nonce[:]), nil
}

// ensureInterfaceAbsent delegates device absence proof to the platform runtime.
func ensureInterfaceAbsent(ctx context.Context, name string) error {
	return runtimeDriver.EnsureAbsent(ctx, name)
}

// startUserspace delegates daemon lifetime and UAPI readiness to the platform runtime.
func startUserspace(ctx context.Context, name string) (awgruntime.Reader, func(), error) {
	return runtimeDriver.Start(ctx, name)
}

// waitHandshake polls only the temporary peer state until a timestamp confirms a handshake or the deadline expires.
func waitHandshake(ctx context.Context, name string, run awgruntime.Reader) error {
	for {
		data, err := run(awgruntime.LatestHandshakes, name)
		if err == nil && hasHandshakeTimestamp(data) {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("AmneziaWG handshake was not confirmed")
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// hasHandshakeTimestamp accepts a nonzero decimal handshake timestamp without retaining peer identifiers.
func hasHandshakeTimestamp(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] == "0" {
			continue
		}
		for _, char := range fields[1] {
			if char < '0' || char > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// initiateHandshake provokes a handshake before traffic is admitted, then restores the profile's keepalive setting.
func initiateHandshake(ctx context.Context, name string, config []byte, run awgruntime.Reader) error {
	probe, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	peer := peerSetting(config, "PublicKey")
	if err := runtimeDriver.Keepalive(probe, name, peer, "1"); err != nil {
		return errors.New("cannot initiate AWG runtime handshake")
	}
	if err := waitHandshake(probe, name, run); err != nil {
		return err
	}
	return restoreKeepalive(name, peer, config, runtimeDriver)
}

// peerKeepaliveSetter updates one peer's keepalive without exposing runtime command output.
type peerKeepaliveSetter interface {
	Keepalive(context.Context, string, string, string) error
}

// restoreKeepalive restores the saved keepalive with its own bounded context after handshake confirmation.
func restoreKeepalive(name, peer string, config []byte, driver peerKeepaliveSetter) error {
	keepalive := peerSetting(config, "PersistentKeepalive")
	if keepalive == "" {
		keepalive = "0"
	}
	restore, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := driver.Keepalive(restore, name, peer, keepalive); err != nil {
		return classifyKeepaliveRestoreError(err)
	}
	return nil
}

// classifyKeepaliveRestoreError distinguishes a bounded runtime timeout without exposing tool output.
func classifyKeepaliveRestoreError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("cannot restore AWG peer keepalive before timeout")
	}
	if errors.Is(err, awgruntime.ErrCommandFailed) {
		return errors.New("cannot restore AWG peer keepalive: Entware awg command failed")
	}
	if errors.Is(err, awgruntime.ErrInvalidKeepaliveRequest) {
		return errors.New("cannot restore AWG peer keepalive: invalid Entware request")
	}
	if errors.Is(err, awgruntime.ErrRuntimeRequiresRoot) {
		return errors.New("cannot restore AWG peer keepalive: runtime is not root")
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("cannot restore AWG peer keepalive: context was cancelled")
	}
	return errors.New("cannot restore AWG peer keepalive")
}

// peerSetting returns one named setting from the validated single-peer UAPI configuration, or empty if absent.
func peerSetting(config []byte, setting string) string {
	for _, line := range strings.Split(string(config), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(key) == setting {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// deleteTemporaryInterface removes only the uniquely named interface owned by this temporary check.
func deleteTemporaryInterface(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if strings.HasPrefix(name, "hchk") && len(name) == 12 {
		_ = runtimeDriver.Delete(ctx, name)
	}
}
