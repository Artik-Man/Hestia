package systemd

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/Artik-Man/Hestia/internal/connectionid"
)

// OfflineVerifier preserves the two historical stop checks used before route retirement.
// Output and Run are command test seams; nil selects the installed systemctl binary.
type OfflineVerifier struct {
	Run    func(context.Context, string, ...string) error
	Output func(context.Context, string, ...string) ([]byte, error)
}

// OutboundDisabled accepts only the historical is-active exit 3 proof, never an execution failure.
func (v OfflineVerifier) OutboundDisabled(ctx context.Context) error {
	run := v.Run
	if run == nil {
		run = func(ctx context.Context, name string, args ...string) error {
			return exec.CommandContext(ctx, name, args...).Run()
		}
	}
	err := run(ctx, executable, "is-active", "--quiet", "hestia-sing-box.service")
	if err == nil {
		return errors.New("Hestia outbound is still active")
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		return errors.New("cannot confirm Hestia outbound is stopped")
	}
	return nil
}

// RetirementOffline requires inactive or failed ActiveState for both router and selected AWG unit.
func (v OfflineVerifier) RetirementOffline(ctx context.Context, id string, legacy bool) error {
	if !connectionid.ValidConnectionID(id) {
		return ErrInvalid
	}
	instance := "hestia-awg@" + id + ".service"
	if legacy {
		instance = "hestia-awg.service"
	}
	output := v.Output
	if output == nil {
		output = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	for _, unit := range []string{"hestia-sing-box.service", instance} {
		data, err := output(ctx, executable, "show", "--property=ActiveState", "--value", unit)
		state := strings.TrimSpace(string(data))
		if err != nil || (state != "inactive" && state != "failed") {
			return errors.New("cannot confirm AWG retirement is offline")
		}
	}
	return nil
}
