package binding

import (
	"context"

	"github.com/Artik-Man/Hestia/internal/platform"
	"github.com/Artik-Man/Hestia/internal/services"
)

// serviceManager returns the installed platform adapter or a command-backed adapter for isolated engines.
func (e Engine) serviceManager() services.Manager {
	if e.services != nil {
		return e.services
	}
	return platform.Services(e.run)
}

// serviceActive permits preserving a shared process only when the platform confirms it is active.
func (e Engine) serviceActive(ctx context.Context, kind services.Kind) bool {
	state, err := e.serviceManager().Status(ctx, services.Service{Kind: kind})
	return err == nil && state == services.Active
}

// requireServiceActive preserves platform errors and rejects unconfirmed activity before publication.
func (e Engine) requireServiceActive(ctx context.Context, kind services.Kind) error {
	state, err := e.serviceManager().Status(ctx, services.Service{Kind: kind})
	if err != nil {
		return err
	}
	if state != services.Active {
		return ErrUnavailable
	}
	return nil
}
