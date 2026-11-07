package platform

import (
	"context"
	"errors"

	"github.com/Artik-Man/Hestia/internal/services"
)

// ErrUnavailable indicates that the selected platform adapter has no verified implementation.
var ErrUnavailable = errors.New("platform capability is not implemented")

// unavailableServices never starts or stops processes on an unsupported platform build.
type unavailableServices struct{}

// Start refuses to start a service without a verified platform lifecycle adapter.
func (unavailableServices) Start(context.Context, ...services.Service) error { return ErrUnavailable }

// Stop refuses to claim a service was stopped without a verified platform lifecycle adapter.
func (unavailableServices) Stop(context.Context, ...services.Service) error { return ErrUnavailable }

// Status returns Unknown because no process supervisor can prove the service state.
func (unavailableServices) Status(context.Context, services.Service) (services.State, error) {
	return services.Unknown, ErrUnavailable
}

// AWGTemplateInstalled reports no template and an error while the platform adapter is unavailable.
func (unavailableServices) AWGTemplateInstalled() (bool, error) { return false, ErrUnavailable }

// unavailableOffline refuses stop proofs until the platform can identify and inspect owned processes.
type unavailableOffline struct{}

// OutboundDisabled refuses to infer that the outbound service is stopped.
func (unavailableOffline) OutboundDisabled(context.Context) error { return ErrUnavailable }

// RetirementOffline refuses to remove guards without a verified stop proof.
func (unavailableOffline) RetirementOffline(context.Context, string, bool) error {
	return ErrUnavailable
}
