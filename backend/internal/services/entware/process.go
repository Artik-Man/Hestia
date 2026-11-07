//go:build linux

package entware

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/connectionid"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/storage"
)

const (
	stopGracePeriod  = 5 * time.Second
	startGracePeriod = 100 * time.Millisecond
)

type processKey struct {
	kind services.Kind
	id   string
}

type processEntry struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	started time.Time
	config  [32]byte
	done    chan struct{}
}

type processTable struct {
	mu      sync.Mutex
	entries map[processKey]*processEntry
}

type processSpec struct {
	path string
	args []string
}

// serviceSpec validates the closed service identity and returns a fixed Entware command.
func serviceSpec(service services.Service) (processSpec, error) {
	layout := storage.Installed()
	if service.Kind == services.AWG {
		if service.Instance != "" && !connectionid.ValidConnectionID(service.Instance) {
			return processSpec{}, ErrInvalid
		}
		args := []string{"-awg-runtime"}
		if service.Instance != "" {
			args = append(args, service.Instance)
		}
		return processSpec{path: "/opt/bin/hestia", args: args}, nil
	}
	if service.Instance != "" {
		return processSpec{}, ErrInvalid
	}
	switch service.Kind {
	case services.Controller:
		return processSpec{path: "/opt/bin/hestia", args: []string{"-watch", "-quality", "-config", layout.Snapshot, "-interval", "1s"}}, nil
	case services.Router:
		return processSpec{path: "/opt/lib/ld-linux-aarch64.so.1", args: []string{"--library-path", "/opt/lib:/opt/lib/hestia", "/opt/lib/hestia/sing-box", "run", "-c", layout.BackendConfig}}, nil
	case services.BindingWatch:
		return processSpec{path: "/opt/bin/hestia", args: []string{"-watch-pending-binding"}}, nil
	case services.Panel:
		listen, err := panelListen()
		if err != nil {
			return processSpec{}, err
		}
		return processSpec{path: "/opt/bin/hestia-panel", args: []string{
			"-listen", listen, "-assets", layout.PanelAssets, "-snapshot", layout.Snapshot,
			"-dns-report", layout.DNSReport,
			"-geoip-index", layout.GeoIPIndex, "-quality-settings", layout.QualitySettings,
			"-quality-report", layout.QualityReport,
			"-enable-bindings", "-enable-group-order", "-enable-domain-lists", "-enable-awg",
			"-enable-group-create", "-enable-group-delete", "-enable-exit-move", "-enable-physical", "-enable-hysteria2",
		}}, nil
	case services.DNS:
		return processSpec{path: "/opt/bin/hestia", args: []string{"dns", layout.DNSConfig}}, nil
	case services.SmokeFresh, services.SmokeCurrent:
		return processSpec{}, ErrUnavailable
	default:
		return processSpec{}, ErrInvalid
	}
}

// panelListen reads the optional exact private listener address, defaulting to loopback.
func panelListen() (string, error) {
	path := storage.Installed().PanelListen
	data, err := readManagedFile(path, 128)
	if errors.Is(err, os.ErrNotExist) {
		return "127.0.0.1:8080", nil
	}
	if err != nil {
		return "", errors.New("panel listener configuration is unavailable")
	}
	listen := strings.TrimSpace(string(data))
	host, portString, err := net.SplitHostPort(listen)
	address, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.ParseUint(portString, 10, 16)
	if err != nil || addressErr != nil || portErr != nil || port == 0 || (!address.IsLoopback() && !address.IsPrivate()) {
		return "", errors.New("panel listener must use one loopback or private IP address")
	}
	return listen, nil
}

// key validates a role and returns the stable in-memory process identity.
func key(service services.Service) (processKey, error) {
	if _, err := serviceSpec(service); err != nil {
		return processKey{}, err
	}
	return processKey{kind: service.Kind, id: service.Instance}, nil
}

// start launches one fixed service and retains its process handle until Wait confirms exit.
func (t *processTable) start(ctx context.Context, service services.Service) error {
	identity, err := key(service)
	if err != nil {
		return err
	}
	spec, err := serviceSpec(service)
	if err != nil {
		return err
	}
	if service.Kind == services.DNS {
		if _, err := readManagedFile(storage.Installed().DNSConfig, 64<<10); err != nil {
			return errors.New("managed DNS configuration is unavailable")
		}
	}
	t.mu.Lock()
	if t.entries == nil {
		t.entries = make(map[processKey]*processEntry)
	}
	if existing := t.entries[identity]; existing != nil {
		select {
		case <-existing.done:
			delete(t.entries, identity)
		default:
			t.mu.Unlock()
			return nil
		}
	}
	logPath := filepath.Join(storage.Installed().Runtime, fmt.Sprintf("service-%d.log", service.Kind))
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		t.mu.Unlock()
		return fmt.Errorf("cannot prepare service log: %w", err)
	}
	logFlags := os.O_CREATE | os.O_APPEND | os.O_WRONLY | syscall.O_NOFOLLOW
	if service.Kind == services.Controller {
		logFlags |= os.O_TRUNC
	}
	logFile, err := os.OpenFile(logPath, logFlags, 0600)
	if err != nil {
		t.mu.Unlock()
		return fmt.Errorf("cannot open service log: %w", err)
	}
	if info, err := logFile.Stat(); err != nil || !info.Mode().IsRegular() {
		_ = logFile.Close()
		t.mu.Unlock()
		return errors.New("managed service log is not a regular file")
	}
	if err := logFile.Chmod(0600); err != nil {
		_ = logFile.Close()
		t.mu.Unlock()
		return fmt.Errorf("cannot secure service log: %w", err)
	}
	if service.Kind == services.Controller {
		if err := prepareQualityPaths(ctx); err != nil {
			_ = logFile.Close()
			t.mu.Unlock()
			return err
		}
	}
	if service.Kind == services.DNS {
		if err := prepareDNSPaths(ctx); err != nil {
			_ = logFile.Close()
			t.mu.Unlock()
			return err
		}
	}
	if service.Kind == services.BindingWatch {
		watchContext, cancel := context.WithCancel(context.Background())
		entry := &processEntry{cancel: cancel, started: time.Now(), done: make(chan struct{})}
		t.entries[identity] = entry
		t.mu.Unlock()
		go func() {
			t.watchBindingMarker(watchContext, spec, logFile)
			_ = logFile.Close()
			close(entry.done)
		}()
		timer := time.NewTimer(startGracePeriod)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-entry.done:
			return errors.New("binding watcher exited during startup")
		case <-timer.C:
			return nil
		}
	}
	var configDigest [32]byte
	if service.Kind == services.Router || service.Kind == services.DNS {
		configPath, limit := storage.Installed().BackendConfig, int64(8<<20)
		if service.Kind == services.DNS {
			configPath, limit = storage.Installed().DNSConfig, 64<<10
		}
		data, err := readManagedFile(configPath, limit)
		if err != nil {
			_ = logFile.Close()
			t.mu.Unlock()
			return errors.New("managed service configuration is unavailable")
		}
		configDigest = sha256.Sum256(data)
	}
	command := exec.Command(spec.path, spec.args...)
	command.Env = []string{
		"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"HESTIA_MANAGED_SERVICE=" + managedServiceRole(service.Kind),
	}
	command.Stdout, command.Stderr = logFile, logFile
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.mu.Unlock()
		return fmt.Errorf("cannot start managed service: %w", err)
	}
	entry := &processEntry{command: command, started: time.Now(), config: configDigest, done: make(chan struct{})}
	t.entries[identity] = entry
	t.mu.Unlock()
	go func() {
		_ = command.Wait()
		_ = logFile.Close()
		close(entry.done)
	}()
	timer := time.NewTimer(startGracePeriod)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-entry.done:
		return errors.New("managed service exited during startup")
	case <-timer.C:
		return nil
	}
}

// prepareQualityPaths runs the installed profile exporter before enabling controller carrier and probe checks.
func prepareQualityPaths(parent context.Context) error {
	layout := storage.Installed()
	if err := os.MkdirAll(layout.QualityRuntime, 0700); err != nil {
		return errors.New("quality runtime directory is unavailable")
	}
	info, err := os.Lstat(layout.QualityRuntime)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("quality runtime directory is invalid")
	}
	if err := os.Chmod(layout.QualityRuntime, 0700); err != nil {
		return errors.New("quality runtime directory cannot be secured")
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/opt/bin/python3", "-I", "/opt/lib/hestia/profile.py", "--quality-paths", layout.BackendConfig, layout.QualityRuntime)
	command.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if err := command.Run(); err != nil {
		return errors.New("cannot prepare confined quality paths")
	}
	if _, err := readManagedFile(filepath.Join(layout.QualityRuntime, "paths.json"), 1<<20); err != nil {
		return errors.New("quality path export failed validation")
	}
	return nil
}

// prepareDNSPaths exports confined DNS egress paths for the current sing-box configuration.
func prepareDNSPaths(parent context.Context) error {
	layout := storage.Installed()
	directory := filepath.Dir(layout.DNSPaths)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return errors.New("DNS runtime directory is unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("DNS runtime directory is invalid")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return errors.New("DNS runtime directory cannot be secured")
	}
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/opt/bin/python3", "-I", "/opt/lib/hestia/profile.py", "--dns-paths", layout.BackendConfig, directory)
	command.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if err := command.Run(); err != nil {
		return errors.New("cannot prepare confined DNS paths")
	}
	if _, err := readManagedFile(layout.DNSPaths, 1<<20); err != nil {
		return errors.New("DNS path export failed validation")
	}
	return nil
}

// managedServiceRole returns the fixed non-secret role marker used to identify Entware child processes.
func managedServiceRole(kind services.Kind) string {
	switch kind {
	case services.Controller:
		return "controller"
	case services.Router:
		return "router"
	case services.BindingWatch:
		return "binding-watch"
	case services.AWG:
		return "awg"
	case services.Panel:
		return "panel"
	case services.DNS:
		return "dns"
	default:
		return "unknown"
	}
}

// watchBindingMarker runs the one-shot recovery command only while a pending binding journal exists.
func (t *processTable) watchBindingMarker(ctx context.Context, spec processSpec, logFile *os.File) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		marker := filepath.Join(storage.Installed().Config, ".binding-pending")
		if _, err := os.Lstat(marker); err == nil {
			command := exec.CommandContext(ctx, spec.path, spec.args...)
			command.Env = []string{
				"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"LANG=C",
				"HESTIA_MANAGED_SERVICE=binding-watch",
			}
			command.Stdout, command.Stderr = logFile, logFile
			command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
			_ = command.Run()
		} else if !errors.Is(err, os.ErrNotExist) {
			_, _ = fmt.Fprintln(logFile, "cannot inspect binding recovery marker")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// stop signals the retained process, escalates after a bounded grace period and waits for exit.
func (t *processTable) stop(ctx context.Context, service services.Service) error {
	identity, err := key(service)
	if err != nil {
		return err
	}
	t.mu.Lock()
	entry := t.entries[identity]
	t.mu.Unlock()
	if entry == nil {
		return nil
	}
	if entry.cancel != nil {
		entry.cancel()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-entry.done:
			t.remove(identity, entry)
			return nil
		}
	}
	select {
	case <-entry.done:
		t.remove(identity, entry)
		return nil
	default:
	}
	if err := entry.command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return errors.New("cannot stop managed service")
	}
	timer := time.NewTimer(stopGracePeriod)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-entry.done:
		t.remove(identity, entry)
		return nil
	case <-timer.C:
	}
	if err := entry.command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return errors.New("cannot terminate managed service")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-entry.done:
		t.remove(identity, entry)
		return nil
	}
}

// status reports only processes whose handles were created by this supervisor instance.
func (t *processTable) status(service services.Service) (services.State, error) {
	identity, err := key(service)
	if err != nil {
		return services.Unknown, err
	}
	t.mu.Lock()
	entry := t.entries[identity]
	t.mu.Unlock()
	if entry == nil {
		return services.Inactive, nil
	}
	select {
	case <-entry.done:
		t.remove(identity, entry)
		return services.Inactive, nil
	default:
		return services.Active, nil
	}
}

// remove deletes an entry only if it still refers to the completed process handle.
func (t *processTable) remove(identity processKey, entry *processEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.entries[identity] == entry {
		delete(t.entries, identity)
	}
}
