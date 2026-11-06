// Package systemd implements the managed service contract for the existing Linux installation.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/services"
)

const executable = "/usr/bin/systemctl"

// ErrInvalid identifies an unsupported service role or malformed instance before any command runs.
var ErrInvalid = errors.New("invalid managed service identity")

// ErrUnavailable identifies an unsafe or unreadable installed service template.
var ErrUnavailable = errors.New("managed service template unavailable")

// Manager uses fixed systemd paths and bounded commands. Run permits isolated command tests;
// its implementation must preserve caller cancellation and omit private output from errors.
// The zero value selects the production command runner.
type Manager struct {
	Run func(context.Context, string, ...string) error
}

// unit maps a known logical role to its fixed systemd name, checking instance input first.
func unit(service services.Service) (string, error) {
	if service.Kind == services.AWG {
		if !awg.ValidConnectionID(service.Instance) {
			return "", ErrInvalid
		}
		return "hestia-awg@" + service.Instance + ".service", nil
	}
	if service.Instance != "" {
		return "", ErrInvalid
	}
	switch service.Kind {
	case services.Controller:
		return "hestia.service", nil
	case services.Router:
		return "hestia-sing-box.service", nil
	case services.SmokeFresh:
		return "hestia-smoke@fresh.service", nil
	case services.SmokeCurrent:
		return "hestia-smoke@current.service", nil
	case services.BindingWatch:
		return "hestia-binding-watch.path", nil
	default:
		return "", ErrInvalid
	}
}

// run executes a systemctl command with the existing deadline and secret-free error contract.
func (m Manager) run(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if m.Run != nil {
		return m.Run(ctx, executable, args...)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl failed: %w", err)
	}
	return nil
}

// change validates the complete batch before executing it once in the caller's requested order.
func (m Manager) change(ctx context.Context, operation string, batch []services.Service) error {
	if len(batch) == 0 {
		return ErrInvalid
	}
	args := []string{operation}
	for _, service := range batch {
		name, err := unit(service)
		if err != nil {
			return err
		}
		args = append(args, name)
	}
	return m.run(ctx, args...)
}

// Start starts the ordered batch; success confirms command completion, not traffic readiness.
func (m Manager) Start(ctx context.Context, batch ...services.Service) error {
	return m.change(ctx, "start", batch)
}

// Stop stops the ordered batch; an error may follow partial execution and requires caller recovery.
func (m Manager) Stop(ctx context.Context, batch ...services.Service) error {
	return m.change(ctx, "stop", batch)
}

// Status preserves is-active errors while distinguishing exit code 3 from unknown failures.
func (m Manager) Status(ctx context.Context, service services.Service) (services.State, error) {
	name, err := unit(service)
	if err != nil {
		return services.Unknown, err
	}
	err = m.run(ctx, "is-active", "--quiet", name)
	if ctx.Err() != nil {
		return services.Unknown, ctx.Err()
	}
	if err == nil {
		return services.Active, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 3 {
		return services.Inactive, err
	}
	return services.Unknown, err
}

// AWGTemplateInstalled checks fixed unit locations, rejecting symbolic links and nonregular files.
func (m Manager) AWGTemplateInstalled() (bool, error) {
	for _, path := range []string{"/etc/systemd/system/hestia-awg@.service", "/lib/systemd/system/hestia-awg@.service", "/usr/lib/systemd/system/hestia-awg@.service"} {
		info, err := os.Lstat(path)
		if err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return false, ErrUnavailable
			}
			return true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return false, ErrUnavailable
		}
	}
	return false, nil
}
