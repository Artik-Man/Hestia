// Package services defines platform-independent identities and lifecycle operations for managed Hestia services.
package services

import "context"

// Kind names the closed set of service roles understood by the application.
type Kind uint8

const (
	Controller Kind = iota + 1
	Router
	SmokeFresh
	SmokeCurrent
	BindingWatch
	AWG
)

// Service identifies a role and, for AWG only, its validated connection instance.
// Adapters reject unknown roles and invalid or unexpected instance values before execution.
type Service struct {
	Kind     Kind
	Instance string
}

// State distinguishes platform activity results from an indeterminate result.
// Inactive means not active; it does not prove process absence or permit guard removal.
type State uint8

const (
	Unknown State = iota
	Active
	Inactive
)

// Manager controls application service roles using the platform's lifecycle mechanism.
// Start and Stop can partially succeed on error; the caller owns transactional recovery.
// Status returns Inactive only for a confirmed not-active result, retaining the platform error
// so callers requiring activity can propagate it. Unknown never proves a stopped process.
type Manager interface {
	Start(context.Context, ...Service) error
	Stop(context.Context, ...Service) error
	Status(context.Context, Service) (State, error)
	AWGTemplateInstalled() (bool, error)
}
