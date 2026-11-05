//go:build linux

package awg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	awgGoPath   = "/usr/local/lib/hestia/amneziawg-go"
	awgToolPath = "/usr/local/bin/awg"
	ipToolPath  = "/usr/sbin/ip"
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
	configDir, err := os.MkdirTemp("/run/hestia-awg", "check-")
	if err != nil {
		return errors.New("cannot create private temporary runtime directory")
	}
	defer os.RemoveAll(configDir)
	configPath := filepath.Join(configDir, "profile.conf")
	if err := os.WriteFile(configPath, profile.RuntimeConfig, 0600); err != nil {
		return errors.New("cannot stage temporary AmneziaWG settings")
	}
	if err := runAWG(ctx, awgToolPath, "setconf", name, configPath); err != nil {
		return errors.New("userspace runtime rejected the AmneziaWG profile")
	}
	if err := runAWG(ctx, ipToolPath, "link", "set", "dev", name, "up"); err != nil {
		return errors.New("cannot activate temporary AmneziaWG interface")
	}
	if err := runAWG(ctx, awgToolPath, "set", name, "peer", peerSetting(profile.RuntimeConfig, "PublicKey"), "persistent-keepalive", "1"); err != nil {
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

// ensureInterfaceAbsent refuses to reuse an existing host interface with the generated temporary name.
func ensureInterfaceAbsent(ctx context.Context, name string) error {
	_, err := exec.CommandContext(ctx, ipToolPath, "link", "show", "dev", name).Output()
	if err == nil {
		return errors.New("temporary AmneziaWG interface name already exists")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil
	}
	return errors.New("cannot verify temporary interface name")
}

// startUserspace launches the foreground daemon and waits until its control interface responds.
func startUserspace(ctx context.Context, name string) (func(string, ...string) ([]byte, error), func(), error) {
	command := exec.CommandContext(ctx, awgGoPath, "-f", name)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Start(); err != nil {
		return nil, nil, errors.New("cannot start AmneziaWG userspace daemon")
	}
	stop := func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}
	run := func(path string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, path, args...).Output()
	}
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := run(awgToolPath, "show", name, "public-key"); err == nil {
			return run, stop, nil
		}
		select {
		case <-ctx.Done():
			stop()
			return nil, nil, errors.New("AmneziaWG userspace interface did not become ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
	stop()
	return nil, nil, errors.New("AmneziaWG userspace interface did not become ready")
}

// runAWG executes one fixed system binary with structured arguments and discards potentially sensitive output.
func runAWG(ctx context.Context, path string, args ...string) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

// waitHandshake polls only the temporary peer state until a timestamp confirms a handshake or the deadline expires.
func waitHandshake(ctx context.Context, name string, run func(string, ...string) ([]byte, error)) error {
	for {
		data, err := run(awgToolPath, "show", name, "latest-handshakes")
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
func initiateHandshake(ctx context.Context, name string, config []byte, run func(string, ...string) ([]byte, error)) error {
	probe, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	peer := peerSetting(config, "PublicKey")
	if err := runAWG(probe, awgToolPath, "set", name, "peer", peer, "persistent-keepalive", "1"); err != nil {
		return errors.New("cannot initiate AWG runtime handshake")
	}
	if err := waitHandshake(probe, name, run); err != nil {
		return err
	}
	keepalive := peerSetting(config, "PersistentKeepalive")
	if keepalive == "" {
		keepalive = "0"
	}
	if err := runAWG(probe, awgToolPath, "set", name, "peer", peer, "persistent-keepalive", keepalive); err != nil {
		return errors.New("cannot restore AWG peer keepalive")
	}
	return nil
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
		_ = runAWG(ctx, ipToolPath, "link", "delete", "dev", name)
	}
}
