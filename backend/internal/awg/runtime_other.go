//go:build !linux

package awg

import (
	"context"
	"errors"
	"os"
)

// InstalledRuntime is unavailable on hosts that cannot create Linux userspace TUN interfaces.
type InstalledRuntime struct{}

// Check fails closed outside Linux instead of pretending that the profile was probed.
func (InstalledRuntime) Check(context.Context, Profile) error {
	return errors.New("AmneziaWG userspace check requires Linux")
}

// ServeReadyConnector fails closed outside Linux because it cannot manage the TUN device or policy routes.
func (InstalledRuntime) ServeReadyConnector(context.Context, string) error {
	return errors.New("AmneziaWG userspace service requires Linux")
}

// RetireStoppedConnector accepts an absent manifest on development hosts and fails closed if cleanup needs Linux.
func RetireStoppedConnector(_ context.Context, id string, slot int, legacy bool) error {
	if !ValidConnectionID(id) || slot < 0 || slot >= SlotCount {
		return errors.New("invalid AWG runtime identity")
	}
	path := "/run/hestia-awg/routes.json"
	if !legacy {
		path += "." + id
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("AmneziaWG policy cleanup requires Linux")
}

// ConfirmConnectorGuards fails closed on development hosts without Linux policy routing.
func ConfirmConnectorGuards(context.Context, string, int) error {
	return errors.New("AmneziaWG guard verification requires Linux")
}
