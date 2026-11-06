// Package awgruntime isolates fixed Linux AmneziaWG process and interface operations from connector coordination.
package awgruntime

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

const (
	daemon = "/usr/local/lib/hestia/amneziawg-go"
	tool   = "/usr/local/bin/awg"
	ip     = "/usr/sbin/ip"
)

// Query selects public runtime observations needed by the coordinator.
type Query uint8

const (
	PublicKey Query = iota + 1
	LatestHandshakes
	ListenPort
	Endpoints
)

// Reader reads one fixed AWG observation for an interface using the daemon lifetime context.
type Reader func(Query, string) ([]byte, error)

// Driver exposes semantic daemon/tool operations without executable names or arbitrary argv.
type Driver interface {
	EnsureAbsent(context.Context, string) error
	Start(context.Context, string) (Reader, func(), error)
	Configure(context.Context, string, string) error
	Activate(context.Context, string) error
	Address(context.Context, string, string) error
	Keepalive(context.Context, string, string, string) error
	Endpoint(context.Context, string, string, string) error
	Observe(context.Context, Query, string) ([]byte, error)
	Delete(context.Context, string) error
}

// Linux executes the existing pinned AWG daemon and host iproute2 tools.
type Linux struct {
	command func(context.Context, string, ...string) *exec.Cmd
}

// cmd selects the fixed-command test seam or standard process execution.
func (l Linux) cmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if l.command != nil {
		return l.command(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// EnsureAbsent accepts only iproute2 exit 1 as proof that a generated device does not exist.
func (l Linux) EnsureAbsent(ctx context.Context, name string) error {
	_, err := l.cmd(ctx, ip, "link", "show", "dev", name).Output()
	if err == nil {
		return errors.New("temporary AmneziaWG interface name already exists")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return nil
	}
	return errors.New("cannot verify temporary interface name")
}

// Start runs a foreground daemon and returns observation and cleanup functions only after UAPI responds.
func (l Linux) Start(ctx context.Context, name string) (Reader, func(), error) {
	command := l.cmd(ctx, daemon, "-f", name)
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
	read := func(q Query, device string) ([]byte, error) { return l.Observe(ctx, q, device) }
	for attempt := 0; attempt < 50; attempt++ {
		if _, err := read(PublicKey, name); err == nil {
			return read, stop, nil
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

// Observe maps a closed query to fixed awg show arguments without exposing child stderr.
func (l Linux) Observe(ctx context.Context, q Query, name string) ([]byte, error) {
	var field string
	switch q {
	case PublicKey:
		field = "public-key"
	case LatestHandshakes:
		field = "latest-handshakes"
	case ListenPort:
		field = "listen-port"
	case Endpoints:
		field = "endpoints"
	default:
		return nil, errors.New("invalid AWG observation")
	}
	return l.cmd(ctx, tool, "show", name, field).Output()
}

// discard runs a fixed adapter-owned binary and never exposes potentially private command output.
func (l Linux) discard(ctx context.Context, path string, args ...string) error {
	c := l.cmd(ctx, path, args...)
	c.Stdout, c.Stderr = io.Discard, io.Discard
	return c.Run()
}

// Configure applies the already validated private profile at the trusted runtime path.
func (l Linux) Configure(ctx context.Context, name, path string) error {
	return l.discard(ctx, tool, "setconf", name, path)
}

// Activate raises only the selected owned interface.
func (l Linux) Activate(ctx context.Context, name string) error {
	return l.discard(ctx, ip, "link", "set", "dev", name, "up")
}

// Address assigns the connector address without creating an implicit prefix route.
func (l Linux) Address(ctx context.Context, name, address string) error {
	return l.discard(ctx, ip, "addr", "add", address, "dev", name, "noprefixroute")
}

// Keepalive applies the validated peer keepalive value for handshake checks and restoration.
func (l Linux) Keepalive(ctx context.Context, name, peer, value string) error {
	return l.discard(ctx, tool, "set", name, "peer", peer, "persistent-keepalive", value)
}

// Endpoint points the validated peer at its local relay endpoint.
func (l Linux) Endpoint(ctx context.Context, name, peer, endpoint string) error {
	return l.discard(ctx, tool, "set", name, "peer", peer, "endpoint", endpoint)
}

// Delete removes the interface whose ownership has already been verified by the caller.
func (l Linux) Delete(ctx context.Context, name string) error {
	return l.discard(ctx, ip, "link", "delete", "dev", name)
}
