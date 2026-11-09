//go:build linux && keenetic

package binding

import (
	"bytes"
	"context"
	"errors"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/profileexec"
)

// SetKeeneticIngress transactionally enables or removes the OpkgTun inbound while retaining the active Hestia profile.
func (e Engine) SetKeeneticIngress(ctx context.Context, enabled bool) error {
	var currentSnapshot []byte
	check := func(data []byte, staged bool) error {
		if _, err := controller.CheckSnapshot(data); err != nil {
			return ErrUnavailable
		}
		if !staged {
			currentSnapshot = bytes.Clone(data)
			return nil
		}
		if !bytes.Equal(currentSnapshot, data) {
			return errors.New("Keenetic ingress migration changed the controller snapshot")
		}
		return nil
	}
	prepare := func(stage string) error {
		return e.profileCompiler().Apply(ctx, profileexec.Request{
			Operation: profileexec.KeeneticIngress, Source: e.dir, Stage: stage, Enabled: enabled,
		})
	}
	return e.apply(ctx, prepare, check, false)
}
