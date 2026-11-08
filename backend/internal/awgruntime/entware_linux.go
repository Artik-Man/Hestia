//go:build linux && keenetic

package awgruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/storage"
)

const (
	entwareDaemon          = "/opt/bin/amneziawg-go"
	entwareTool            = "/opt/bin/awg"
	entwareIP              = "/opt/sbin/ip"
	entwareUAPIRuntime     = "/opt/tmp/hestia-awg-uapi-26b84f/runtime/amneziawg"
	maxRuntimeOutput       = 1 << 20
	runtimeReadyTimeout    = 5 * time.Second
	runtimeStopGracePeriod = 2 * time.Second
)

var entwareInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)
var entwareDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// Entware controls the pinned static AWG runtime and Entware ip/awg tools on Keenetic.
type Entware struct{}

// EnsureAbsent proves that the requested interface name is not present in sysfs.
func (Entware) EnsureAbsent(_ context.Context, name string) error {
	if !entwareInterfaceName.MatchString(name) {
		return errors.New("invalid AWG interface name")
	}
	_, err := os.Lstat(filepath.Join("/sys/class/net", name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot verify AWG interface absence")
	}
	return errors.New("AWG interface name is already present")
}

// Start starts the foreground AWG daemon and waits until its private UAPI socket answers.
func (Entware) Start(ctx context.Context, name string) (Reader, func(), error) {
	if err := requireEntwareRoot(); err != nil {
		return nil, nil, err
	}
	if err := (Entware{}).EnsureAbsent(ctx, name); err != nil {
		return nil, nil, err
	}
	if err := prepareEntwareUAPIRuntime(); err != nil {
		return nil, nil, err
	}
	socketPath := filepath.Join(entwareUAPIRuntime, name+".sock")
	if err := clearStaleEntwareUAPISocket(socketPath); err != nil {
		return nil, nil, err
	}
	command := exec.CommandContext(ctx, entwareDaemon, "-f", name)
	command.Env = []string{
		"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"HESTIA_MANAGED_SERVICE=awg",
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		return nil, nil, errors.New("cannot start Entware AWG daemon")
	}
	waited := make(chan struct{})
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if command.Process != nil {
				_ = command.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-waited:
			case <-time.After(runtimeStopGracePeriod):
				if command.Process != nil {
					_ = command.Process.Kill()
				}
				<-waited
			}
			_ = clearStaleEntwareUAPISocket(socketPath)
		})
	}
	go func() {
		_ = command.Wait()
		close(waited)
	}()
	reader := func(query Query, device string) ([]byte, error) {
		return (Entware{}).Observe(ctx, query, device)
	}
	timer := time.NewTimer(runtimeReadyTimeout)
	defer timer.Stop()
	for {
		if _, err := reader(PublicKey, name); err == nil {
			return reader, stop, nil
		}
		select {
		case <-ctx.Done():
			stop()
			return nil, nil, errors.New("Entware AWG daemon startup was cancelled")
		case <-waited:
			_ = clearStaleEntwareUAPISocket(socketPath)
			return nil, nil, errors.New("Entware AWG daemon exited during startup")
		case <-timer.C:
			stop()
			return nil, nil, errors.New("Entware AWG UAPI did not become ready")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Configure applies a private profile created under the installed AWG runtime directory.
func (Entware) Configure(ctx context.Context, name, path string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) || !privateEntwareConfig(path) {
		return errors.New("invalid Entware AWG configuration request")
	}
	return runEntwareCommand(ctx, entwareTool, "setconf", name, path)
}

// Activate raises only the validated AWG interface.
func (Entware) Activate(ctx context.Context, name string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) {
		return errors.New("invalid AWG interface name")
	}
	return runEntwareCommand(ctx, entwareIP, "link", "set", "dev", name, "up")
}

// Address assigns one valid address prefix without changing the executable selection.
func (Entware) Address(ctx context.Context, name, address string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) {
		return errors.New("invalid AWG interface name")
	}
	if _, err := netip.ParsePrefix(address); err != nil {
		return errors.New("invalid AWG interface address")
	}
	return runEntwareCommand(ctx, entwareIP, "addr", "add", address, "dev", name, "noprefixroute")
}

// Keepalive applies the bounded decimal keepalive value to one validated peer.
func (Entware) Keepalive(ctx context.Context, name, peer, value string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) || !validPeerKey(peer) || !validKeepalive(value) {
		return ErrInvalidKeepaliveRequest
	}
	return runEntwareCommand(ctx, entwareTool, "set", name, "peer", peer, "persistent-keepalive", value)
}

// Endpoint sets one validated peer endpoint without exposing tool output.
func (Entware) Endpoint(ctx context.Context, name, peer, endpoint string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) || !validPeerKey(peer) {
		return errors.New("invalid AWG endpoint request")
	}
	host, port, err := net.SplitHostPort(endpoint)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || !validEntwareEndpointHost(host) || portErr != nil || portNumber == 0 || strconv.FormatUint(portNumber, 10) != port {
		return errors.New("invalid AWG endpoint")
	}
	return runEntwareCommand(ctx, entwareTool, "set", name, "peer", peer, "endpoint", endpoint)
}

// Observe reads one fixed runtime field and caps the returned command output.
func (Entware) Observe(ctx context.Context, query Query, name string) ([]byte, error) {
	if !entwareInterfaceName.MatchString(name) {
		return nil, errors.New("invalid AWG interface name")
	}
	var field string
	switch query {
	case PublicKey:
		field = "public-key"
	case LatestHandshakes:
		field = "latest-handshakes"
	case ListenPort:
		field = "listen-port"
	case Endpoints:
		field = "endpoints"
	case Transfer:
		field = "transfer"
	default:
		return nil, errors.New("invalid AWG runtime observation")
	}
	command := exec.CommandContext(ctx, entwareTool, "show", name, field)
	command.Env = entwareCommandEnvironment()
	var output boundedRuntimeOutput
	command.Stdout, command.Stderr = &output, io.Discard
	if err := command.Run(); err != nil {
		return nil, errors.New("Entware AWG observation failed")
	}
	return bytes.Clone(output.Bytes()), nil
}

// Delete removes only the validated interface name selected by the caller.
func (Entware) Delete(ctx context.Context, name string) error {
	if err := requireEntwareRoot(); err != nil {
		return err
	}
	if !entwareInterfaceName.MatchString(name) {
		return errors.New("invalid AWG interface name")
	}
	return runEntwareCommand(ctx, entwareIP, "link", "delete", "dev", name)
}

// requireEntwareRoot refuses all service mutations unless the process is root.
func requireEntwareRoot() error {
	if os.Geteuid() != 0 {
		return ErrRuntimeRequiresRoot
	}
	return nil
}

// prepareEntwareUAPIRuntime creates the exact private socket directory compiled into the pinned daemon.
func prepareEntwareUAPIRuntime() error {
	for _, path := range []string{"/opt", "/opt/tmp"} {
		if err := verifyEntwareParentDirectory(path); err != nil {
			return err
		}
	}
	for _, path := range []string{
		"/opt/tmp/hestia-awg-uapi-26b84f",
		"/opt/tmp/hestia-awg-uapi-26b84f/runtime",
		entwareUAPIRuntime,
	} {
		if err := ensureEntwarePrivateDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

// clearStaleEntwareUAPISocket removes only an inactive socket entry inside the protected AWG runtime directory.
func clearStaleEntwareUAPISocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("AWG UAPI socket path is already occupied or unavailable")
	}
	connection, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		return errors.New("AWG UAPI socket path is already occupied or unavailable")
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("AWG UAPI socket path is already occupied or unavailable")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("AWG UAPI socket path is already occupied or unavailable")
	}
	return nil
}

// verifyEntwareParentDirectory rejects unsafe mount parents without changing their permissions.
func verifyEntwareParentDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("AWG UAPI parent directory is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !entwareParentIsProtected(stat.Uid, stat.Mode) {
		return errors.New("AWG UAPI parent directory is not root protected")
	}
	return nil
}

// entwareParentIsProtected uses raw Unix mode bits because Entware's Go runtime omits the sticky bit from FileMode.
func entwareParentIsProtected(uid, mode uint32) bool {
	return uid == 0 && (mode&0022 == 0 || mode&01000 != 0)
}

// ensureEntwarePrivateDirectory creates one root-owned runtime directory with private permissions.
func ensureEntwarePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("cannot create private AWG UAPI directory")
		}
		info, err = os.Lstat(path)
	}
	stat, ok := (*syscall.Stat_t)(nil), false
	if err == nil {
		stat, ok = info.Sys().(*syscall.Stat_t)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Uid != 0 {
		return errors.New("AWG UAPI directory path is unsafe")
	}
	if err := os.Chmod(path, 0700); err != nil {
		return errors.New("cannot secure AWG UAPI directory")
	}
	return nil
}

// privateEntwareConfig accepts only a regular private profile below the installed AWG runtime directory.
func privateEntwareConfig(path string) bool {
	runtimeRoot := filepath.Clean(storage.Installed().AWGRuntime)
	root := runtimeRoot + string(os.PathSeparator)
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, root) {
		return false
	}
	parent := filepath.Dir(clean)
	if !verifyPrivateEntwareRuntimePath(runtimeRoot, parent) {
		return false
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

// verifyPrivateEntwareRuntimePath rejects symlinks and writable or non-root-owned parents below the runtime root.
func verifyPrivateEntwareRuntimePath(root, parent string) bool {
	relative, err := filepath.Rel(root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return false
	}
	current := string(os.PathSeparator)
	for _, candidate := range strings.Split(strings.TrimPrefix(filepath.Clean(parent), current), current) {
		current = filepath.Join(current, candidate)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false
		}
	}
	return true
}

// validEntwareEndpointHost accepts an IPv4 literal or an ASCII DNS name without empty labels.
func validEntwareEndpointHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !entwareDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// runEntwareCommand executes a fixed absolute path without a shell and returns no child output.
func runEntwareCommand(ctx context.Context, path string, args ...string) error {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = entwareCommandEnvironment()
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("Entware command deadline exceeded: %w", context.DeadlineExceeded)
		}
		return fmt.Errorf("%w: %s", ErrCommandFailed, filepath.Base(path))
	}
	return nil
}

// entwareCommandEnvironment returns the minimal path and locale needed by the pinned Entware applets.
func entwareCommandEnvironment() []string {
	return []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
}

// validPeerKey accepts the canonical base64 size emitted by the AWG profile parser.
func validPeerKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(decoded) == 32
}

// validKeepalive accepts a scalar or inclusive AmneziaWG interval in the unsigned 16-bit range.
func validKeepalive(value string) bool {
	parts := strings.Split(value, "-")
	if value == "" || len(parts) > 2 {
		return false
	}
	minimum, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil || strconv.FormatUint(minimum, 10) != parts[0] {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	maximum, err := strconv.ParseUint(parts[1], 10, 16)
	return err == nil && strconv.FormatUint(maximum, 10) == parts[1] && minimum <= maximum
}

// boundedRuntimeOutput accumulates child output up to a fixed memory ceiling.
type boundedRuntimeOutput struct {
	bytes.Buffer
}

// Write rejects output that exceeds the fixed runtime observation limit.
func (b *boundedRuntimeOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxRuntimeOutput {
		return 0, errors.New("AWG observation exceeded its output limit")
	}
	return b.Buffer.Write(data)
}
