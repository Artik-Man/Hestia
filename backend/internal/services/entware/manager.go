//go:build linux

package entware

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Artik-Man/Hestia/internal/connectionid"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/storage"
)

// ErrUnavailable indicates that the supervisor cannot prove or perform the requested operation.
var ErrUnavailable = errors.New("Entware service supervisor unavailable")

// ErrInvalid identifies malformed role or instance values rejected before IPC.
var ErrInvalid = errors.New("invalid managed service identity")

// Manager controls the fixed services owned by the local Entware supervisor.
type Manager struct{}

// Start asks the supervisor to start each known service in the requested order.
func (Manager) Start(ctx context.Context, batch ...services.Service) error {
	if len(batch) == 0 {
		return ErrInvalid
	}
	if len(batch) == 1 && batch[0].Instance == "" && (batch[0].Kind == services.SmokeFresh || batch[0].Kind == services.SmokeCurrent) {
		operation := "smoke-fresh"
		if batch[0].Kind == services.SmokeCurrent {
			operation = "smoke-current"
		}
		_, err := requestSupervisor(ctx, request{Operation: operation})
		return err
	}
	for _, service := range batch {
		if _, err := key(service); err != nil {
			return err
		}
	}
	_, err := requestSupervisor(ctx, request{Operation: "start", Services: batch})
	return err
}

// Stop asks the supervisor to stop each retained process and waits for confirmed exit.
func (Manager) Stop(ctx context.Context, batch ...services.Service) error {
	if len(batch) == 0 {
		return ErrInvalid
	}
	for _, service := range batch {
		if _, err := key(service); err != nil {
			return err
		}
	}
	_, err := requestSupervisor(ctx, request{Operation: "stop", Services: batch})
	return err
}

// Status returns only process state confirmed by the running supervisor instance.
func (Manager) Status(ctx context.Context, service services.Service) (services.State, error) {
	if _, err := key(service); err != nil {
		return services.Unknown, err
	}
	output, err := requestSupervisor(ctx, request{Operation: "status", Service: service})
	return output.State, err
}

// AWGTemplateInstalled reports false until a supported Keenetic AWG runtime is implemented.
func (Manager) AWGTemplateInstalled() (bool, error) { return false, nil }

// OfflineVerifier derives stop proof only from supervisor-held process handles.
type OfflineVerifier struct{}

// OutboundDisabled requires a confirmed inactive router process.
func (OfflineVerifier) OutboundDisabled(ctx context.Context) error {
	state, err := (Manager{}).Status(ctx, services.Service{Kind: services.Router})
	if err != nil || state != services.Inactive {
		return ErrUnavailable
	}
	return nil
}

// RetirementOffline refuses retirement while either the router or an AWG role is unknown or active.
func (OfflineVerifier) RetirementOffline(ctx context.Context, id string, legacy bool) error {
	if !connectionid.ValidConnectionID(id) {
		return ErrInvalid
	}
	state, err := (Manager{}).Status(ctx, services.Service{Kind: services.Router})
	if err != nil || state != services.Inactive {
		return ErrUnavailable
	}
	return ErrUnavailable
}

// dnsServiceConfigured reports whether a securely managed optional DNS config is installed.
func dnsServiceConfigured() (bool, error) {
	_, err := readManagedFile(storage.Installed().DNSConfig, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnavailable
	}
	return true, nil
}

// SupervisorReady confirms that all service processes are active in the root-only supervisor table.
func SupervisorReady(ctx context.Context) error {
	kinds := []services.Kind{services.Router, services.Controller, services.BindingWatch, services.Panel}
	configured, err := dnsServiceConfigured()
	if err != nil {
		return fmt.Errorf("managed service %d is not ready", services.DNS)
	}
	if configured {
		kinds = append(kinds, services.DNS)
	}
	for _, kind := range kinds {
		state, err := (Manager{}).Status(ctx, services.Service{Kind: kind})
		if err != nil || state != services.Active {
			return fmt.Errorf("managed service %d is not ready", kind)
		}
	}
	return nil
}
