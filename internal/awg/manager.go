package awg

import (
	"context"
	"errors"
)

var ErrRuntimeUnavailable = errors.New("AmneziaWG userspace check is unavailable")

// Runtime checks one validated profile in a temporary, isolated environment and never publishes it.
type Runtime interface {
	Check(context.Context, Profile) error
}

// Manager coordinates strict profile validation, temporary checks, and private persistence.
type Manager struct {
	store   *Store
	runtime Runtime
}

// NewManager binds an AWG store to the userspace runtime used for temporary profile checks.
func NewManager(store *Store, runtime Runtime) *Manager {
	return &Manager{store: store, runtime: runtime}
}

// Check validates and probes one candidate without writing profile files or changing active exits.
func (m *Manager) Check(ctx context.Context, raw []byte) error {
	profile, err := Parse(raw)
	if err != nil {
		return err
	}
	if m.runtime == nil {
		return ErrRuntimeUnavailable
	}
	return m.runtime.Check(ctx, profile)
}

// Save validates and persists one profile with its public group assignment and priority.
func (m *Manager) Save(metadata Metadata, raw []byte) error {
	return m.store.Save(metadata, raw)
}

// List returns only public metadata for configured AWG connections.
func (m *Manager) List() ([]Metadata, error) {
	return m.store.List()
}

// Delete removes the stored secret profile and its public metadata transactionally.
func (m *Manager) Delete(id string) error {
	return m.store.Delete(id)
}
