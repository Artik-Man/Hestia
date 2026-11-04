//go:build !linux

package awg

import (
	"context"
	"errors"
)

// InstalledRuntime is unavailable on hosts that cannot create Linux userspace TUN interfaces.
type InstalledRuntime struct{}

// Check fails closed outside Linux instead of pretending that the profile was probed.
func (InstalledRuntime) Check(context.Context, Profile) error {
	return errors.New("AmneziaWG userspace check requires Linux")
}

// ServeReadyConnector fails closed outside Linux because it cannot manage the TUN device or policy routes.
func (InstalledRuntime) ServeReadyConnector(context.Context) error {
	return errors.New("AmneziaWG userspace service requires Linux")
}
