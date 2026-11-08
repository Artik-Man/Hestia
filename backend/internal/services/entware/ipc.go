//go:build linux

package entware

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/storage"
)

const maxIPCMessage = 4096
const bootRecoveryLimit = 47 * time.Minute
const supervisorReadyFile = "supervisor.ready"

type request struct {
	Operation string             `json:"operation"`
	Services  []services.Service `json:"services,omitempty"`
	Service   services.Service   `json:"service,omitempty"`
}

type response struct {
	State services.State `json:"state,omitempty"`
	Error string         `json:"error,omitempty"`
}

// RunSupervisor serves root-only lifecycle requests and owns every process it starts.
func RunSupervisor(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("service supervisor must run as root")
	}
	if err := verifyNoOrphanProcesses(); err != nil {
		return err
	}
	path := storage.Installed().ServicesSocket
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot prepare service runtime: %w", err)
	}
	if info, err := os.Lstat(filepath.Dir(path)); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("service runtime directory is not owned by the supervisor")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("cannot secure service runtime: %w", err)
	}
	readyPath := filepath.Join(storage.Installed().Runtime, supervisorReadyFile)
	if err := clearStaleReadyMarker(readyPath); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
			return errors.New("refusing to replace an unowned service socket path")
		}
		if conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return errors.New("service supervisor is already running")
		}
		if err := os.Remove(path); err != nil {
			return errors.New("cannot remove stale service socket")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect service socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("cannot listen for service requests: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return fmt.Errorf("cannot secure service socket: %w", err)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(path)
	}()
	table := processTable{}
	acceptErr := make(chan error, 1)
	var handlers sync.WaitGroup
	go acceptConnections(ctx, listener, &table, &handlers, acceptErr)
	failStartup := func(startupErr error) error {
		_ = listener.Close()
		handlers.Wait()
		_ = stopAll(context.Background(), &table)
		return startupErr
	}
	if err := table.start(context.Background(), services.Service{Kind: services.BindingWatch}); err != nil {
		return failStartup(err)
	}
	if err := awaitBootRecovery(ctx); err != nil {
		return failStartup(err)
	}
	for _, service := range []services.Service{{Kind: services.Router}, {Kind: services.Controller}, {Kind: services.Panel}} {
		if err := table.start(context.Background(), service); err != nil {
			return failStartup(err)
		}
	}
	dnsConfigured, err := dnsServiceConfigured()
	if err != nil {
		return failStartup(err)
	}
	if dnsConfigured {
		if err := table.start(context.Background(), services.Service{Kind: services.DNS}); err != nil {
			return failStartup(err)
		}
	}
	if err := publishReadyMarker(readyPath); err != nil {
		return failStartup(err)
	}
	defer removeReadyMarker(readyPath)
	go watchOptionalDNS(ctx, &table)
	select {
	case err := <-acceptErr:
		if ctx.Err() != nil {
			return stopAll(context.Background(), &table)
		}
		return fmt.Errorf("service socket accept failed: %w", err)
	case <-ctx.Done():
		_ = listener.Close()
		handlers.Wait()
		return stopAll(context.Background(), &table)
	}
}

// watchOptionalDNS reconciles the optional DNS worker after config and router generations change.
func watchOptionalDNS(ctx context.Context, table *processTable) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	backoff := time.Duration(0)
	nextStart := time.Time{}
	activeSince := time.Time{}
	service := services.Service{Kind: services.DNS}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		configured, err := dnsServiceConfigured()
		if err != nil {
			log.Printf("optional DNS configuration is unavailable; stopping worker")
			stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if stopErr := table.stop(stopCtx, service); stopErr != nil {
				log.Printf("optional DNS worker stop failed: %v", stopErr)
			}
			cancel()
			backoff, nextStart, activeSince = 0, time.Time{}, time.Time{}
			continue
		}
		if !configured {
			stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			if stopErr := table.stop(stopCtx, service); stopErr != nil {
				log.Printf("optional DNS worker stop failed: %v", stopErr)
			}
			cancel()
			backoff, nextStart, activeSince = 0, time.Time{}, time.Time{}
			continue
		}
		dnsConfig, err := readManagedFile(storage.Installed().DNSConfig, 64<<10)
		if err != nil {
			continue
		}
		currentDigest := sha256.Sum256(dnsConfig)
		state, err := table.status(service)
		if err != nil {
			log.Printf("optional DNS worker status failed: %v", err)
			continue
		}
		if state == services.Active {
			entry := table.entry(service)
			if entry != nil && entry.config != currentDigest {
				stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				if stopErr := table.stop(stopCtx, service); stopErr != nil {
					log.Printf("optional DNS worker restart failed: %v", stopErr)
				}
				cancel()
				activeSince, nextStart = time.Time{}, time.Time{}
				continue
			}
			if activeSince.IsZero() {
				activeSince = time.Now()
			}
			if time.Since(activeSince) >= 10*time.Second {
				backoff = 0
			}
			continue
		}
		if !activeSince.IsZero() {
			if time.Since(activeSince) < 10*time.Second {
				backoff = nextDNSBackoff(backoff)
			} else {
				backoff = 0
			}
			activeSince = time.Time{}
			nextStart = time.Now().Add(backoff)
		}
		if time.Now().Before(nextStart) {
			continue
		}
		startCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err = table.start(startCtx, service)
		cancel()
		if err == nil {
			activeSince, nextStart = time.Now(), time.Time{}
			continue
		}
		log.Printf("optional DNS worker start failed: %v", err)
		backoff = nextDNSBackoff(backoff)
		nextStart = time.Now().Add(backoff)
	}
}

// nextDNSBackoff doubles restart delays from one second up to a 30-second cap.
func nextDNSBackoff(current time.Duration) time.Duration {
	if current <= 0 {
		return time.Second
	}
	current *= 2
	if current > 30*time.Second {
		return 30 * time.Second
	}
	return current
}

// clearStaleReadyMarker removes only a regular root-owned marker after orphan checks pass.
func clearStaleReadyMarker(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("supervisor readiness marker is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("supervisor readiness marker ownership is invalid")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("cannot clear stale supervisor readiness marker")
	}
	return nil
}

// publishReadyMarker atomically claims the readiness path after all required services have started.
func publishReadyMarker(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot publish supervisor readiness")
	}
	if _, err := file.WriteString("ready\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("cannot write supervisor readiness")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("cannot close supervisor readiness marker")
	}
	return nil
}

// removeReadyMarker removes the marker owned by the current supervisor during shutdown.
func removeReadyMarker(path string) {
	_ = os.Remove(path)
}

// acceptConnections serves requests concurrently so boot recovery can call back into its own supervisor.
func acceptConnections(ctx context.Context, listener net.Listener, table *processTable, handlers *sync.WaitGroup, failures chan<- error) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			failures <- err
			return
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			handleConnection(ctx, connection, table)
		}()
	}
}

// awaitBootRecovery keeps the router stopped until the binding watcher clears an interrupted journal.
func awaitBootRecovery(ctx context.Context) error {
	marker := filepath.Join(storage.Installed().Config, ".binding-pending")
	deadline := time.NewTimer(bootRecoveryLimit)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Lstat(marker); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return errors.New("cannot inspect binding recovery marker")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("binding recovery did not finish before the startup deadline")
		case <-ticker.C:
		}
	}
}

// verifyNoOrphanProcesses prevents a new supervisor from reporting inactive while an old child survives.
func verifyNoOrphanProcesses() error {
	return CheckManagedProcessesStopped()
}

// handleConnection checks Unix peer credentials before accepting one bounded JSON request.
func handleConnection(ctx context.Context, connection net.Conn, table *processTable) {
	defer connection.Close()
	unix, ok := connection.(*net.UnixConn)
	if !ok || !rootPeer(unix) {
		_ = json.NewEncoder(connection).Encode(response{Error: "unauthorized service client"})
		return
	}
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	data, err := io.ReadAll(io.LimitReader(connection, maxIPCMessage+1))
	if err != nil || len(data) > maxIPCMessage {
		_ = json.NewEncoder(connection).Encode(response{Error: "invalid service request"})
		return
	}
	var input request
	if err := json.Unmarshal(data, &input); err != nil {
		_ = json.NewEncoder(connection).Encode(response{Error: "invalid service request"})
		return
	}
	output := dispatch(ctx, table, input)
	_ = json.NewEncoder(connection).Encode(output)
}

// rootPeer verifies the connected process UID from kernel-supplied Unix peer credentials.
func rootPeer(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *syscall.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || controlErr != nil {
		return false
	}
	return credentials != nil && credentials.Uid == 0
}

// dispatch executes a validated lifecycle operation and returns only non-sensitive error text.
func dispatch(ctx context.Context, table *processTable, input request) response {
	switch input.Operation {
	case "start", "stop":
		if len(input.Services) == 0 || len(input.Services) > 8 {
			return response{Error: "invalid service batch"}
		}
		for _, service := range input.Services {
			var err error
			if input.Operation == "start" {
				err = table.start(ctx, service)
			} else {
				err = table.stop(ctx, service)
			}
			if err != nil {
				return response{Error: publicError(err, serviceRole(service.Kind))}
			}
		}
		return response{}
	case "status":
		state, err := table.status(input.Service)
		if err != nil {
			return response{Error: publicError(err, serviceRole(input.Service.Kind))}
		}
		return response{State: state}
	case "smoke-fresh", "smoke-current":
		if err := runSmoke(ctx, table, input.Operation == "smoke-fresh"); err != nil {
			return response{Error: publicError(err, "smoke")}
		}
		return response{}
	default:
		return response{Error: "invalid service operation"}
	}
}

// publicError removes command details and paths from service errors sent over IPC.
func publicError(err error, role string) string {
	if errors.Is(err, ErrUnavailable) {
		return "managed service role unavailable: " + role
	}
	if errors.Is(err, ErrInvalid) {
		return "invalid managed service identity"
	}
	return "managed service operation failed: " + role
}

// serviceRole maps a closed service kind to a non-sensitive diagnostic role name.
func serviceRole(kind services.Kind) string {
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

// stopAll waits for every retained process to exit before the supervisor releases its socket.
func stopAll(ctx context.Context, table *processTable) error {
	table.mu.Lock()
	servicesToStop := make([]services.Service, 0, len(table.entries))
	for identity := range table.entries {
		servicesToStop = append(servicesToStop, services.Service{Kind: identity.kind, Instance: identity.id})
	}
	table.mu.Unlock()
	var failure error
	for _, service := range servicesToStop {
		if err := table.stop(ctx, service); err != nil && failure == nil {
			failure = err
		}
	}
	return failure
}

// requestSupervisor sends one bounded command to the local root-only supervisor.
func requestSupervisor(ctx context.Context, input request) (response, error) {
	var output response
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", storage.Installed().ServicesSocket)
	if err != nil {
		return output, ErrUnavailable
	}
	defer connection.Close()
	deadline := time.Now().Add(25 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = connection.SetDeadline(deadline)
	encoder := json.NewEncoder(connection)
	if err := encoder.Encode(input); err != nil {
		return output, ErrUnavailable
	}
	if unix, ok := connection.(*net.UnixConn); !ok || unix.CloseWrite() != nil {
		return output, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(connection, maxIPCMessage+1))
	if err != nil || len(data) > maxIPCMessage || json.Unmarshal(data, &output) != nil {
		return output, ErrUnavailable
	}
	if output.Error != "" {
		if strings.Contains(output.Error, "unavailable") {
			return output, ErrUnavailable
		}
		if strings.Contains(output.Error, "identity") {
			return output, ErrInvalid
		}
		return output, errors.New(output.Error)
	}
	return output, nil
}
