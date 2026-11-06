// Package physical retains the public physical-network contract and stable errors.
package physical

import "github.com/Artik-Man/Hestia/internal/network"

// Manager is implemented by platform-specific physical network adapters.
type Manager = network.Physical

var (
	ErrInvalid  = network.ErrInvalid
	ErrConflict = network.ErrConflict
	ErrNotFound = network.ErrNotFound
)
