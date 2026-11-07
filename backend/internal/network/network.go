// Package network defines platform-neutral physical networking and VPN policy operations.
package network

import (
	"context"
	"errors"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// SlotCount bounds the tunnel allocation below reserved routing resources.
const SlotCount = 50

// Physical manages only application-owned Wi-Fi profiles and reports public interface state.
// Mutations require the caller's installation lock and restore prior state on failure.
type Physical interface {
	Inventory(context.Context) (panelmodel.PhysicalInventory, error)
	SaveWiFi(context.Context, string, panelmodel.WifiConnectionSettings) error
	DeleteWiFi(context.Context, string) error
}

// Carrier observes a kernel interface link and preserves an unavailable observation as unknown.
type Carrier interface {
	State(string) panelmodel.CarrierState
}

// RouteDescriptor identifies the immutable resources allocated to one VPN instance.
type RouteDescriptor struct {
	Mark, Table, Priority, Device string
	MarkValue                     int
}

// RoutePolicy confines a VPN slot and refuses mutation of foreign routing state.
// Teardown requires successful outbound drain; failures retain remaining guards.
type RoutePolicy interface {
	Descriptor() RouteDescriptor
	Preflight(context.Context) error
	InstallGuard(context.Context) error
	EnsureGuards(context.Context) error
	InstallMarkRules(context.Context) error
	AdoptOwnedState(context.Context) error
	ActivateIPv4(context.Context) error
	VerifyReadyPolicy(context.Context) error
	Teardown(context.Context, func(context.Context) error) error
	OuterBarrier(context.Context, bool, bool, func() error) error
}

var (
	ErrInvalid     = errors.New("invalid physical connection settings")
	ErrConflict    = errors.New("physical connection conflicts with gateway state")
	ErrNotFound    = errors.New("physical connection not found")
	ErrUnsupported = errors.New("physical connection operation is unsupported")
)
