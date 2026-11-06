package binding

import (
	"context"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/services/systemd"
	"testing"
)

// These expected Linux commands keep the transaction regression tests independent of adapter mapping.
const (
	systemctl    = "/usr/bin/systemctl"
	watcher      = "hestia.service"
	router       = "hestia-sing-box.service"
	smokeFresh   = "hestia-smoke@fresh.service"
	smokeCurrent = "hestia-smoke@current.service"
)

// instanceUnit describes the expected Linux instance command in transaction assertions.
func instanceUnit(id string) string { return "hestia-awg@" + id + ".service" }

// statusManager isolates coordinator decisions from the Linux status representation.
type statusManager struct {
	services.Manager
	state services.State
}

// Status returns the requested state without a platform error to exercise portable adapters.
func (m statusManager) Status(context.Context, services.Service) (services.State, error) {
	return m.state, nil
}

// TestServiceActivityRequiresPositiveConfirmation rejects inactive and unknown results even without errors.
func TestServiceActivityRequiresPositiveConfirmation(t *testing.T) {
	for _, state := range []services.State{services.Unknown, services.Inactive, services.Active} {
		engine := Engine{services: statusManager{state: state}}
		err := engine.requireServiceActive(context.Background(), services.BindingWatch)
		if (err == nil) != (state == services.Active) || engine.serviceActive(context.Background(), services.Router) != (state == services.Active) {
			t.Fatalf("state %v produced preflight error %v", state, err)
		}
	}
}

// TestInstalledSelectsLinuxServices verifies production construction supplies the Linux adapter explicitly.
func TestInstalledSelectsLinuxServices(t *testing.T) {
	if _, ok := Installed().services.(systemd.Manager); !ok {
		t.Fatal("installed engine does not select the systemd adapter")
	}
}
