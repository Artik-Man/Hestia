//go:build linux && keenetic

package binding

import (
	"context"
	"errors"
	"reflect"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// SetKeeneticIngress transactionally enables or removes the OpkgTun inbound while retaining the active Hestia profile.
func (e Engine) SetKeeneticIngress(ctx context.Context, enabled bool) error {
	var currentSnapshot controller.Config
	check := func(data []byte, staged bool) error {
		candidate, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if !staged {
			currentSnapshot = candidate
			return nil
		}
		if !keeneticIngressSnapshotAllowed(currentSnapshot, candidate, enabled) {
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

// keeneticIngressSnapshotAllowed preserves the installed topology while allowing ingress enablement to add its one managed WAN exit.
func keeneticIngressSnapshotAllowed(current, candidate controller.Config, enabled bool) bool {
	if reflect.DeepEqual(current, candidate) {
		return true
	}
	if !enabled || len(current.Groups) == 0 || len(candidate.Groups) != len(current.Groups) {
		return false
	}
	defaultExits := current.Groups[0].Exits
	candidateExits := candidate.Groups[0].Exits
	if len(candidateExits) != len(defaultExits)+1 || candidateExits[len(defaultExits)] != keeneticUplinkUnderlayID {
		return false
	}
	groups := append([]routing.Group(nil), candidate.Groups...)
	groups[0].Exits = defaultExits
	normalized := candidate
	normalized.Groups = groups
	return reflect.DeepEqual(current, normalized)
}
