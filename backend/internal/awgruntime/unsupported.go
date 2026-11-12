package awgruntime

import (
	"context"
	"errors"
)

// ErrUnsupported identifies a build without a verified AmneziaWG platform driver.
var ErrUnsupported = errors.New("AmneziaWG runtime is unsupported by this platform build")

// Unsupported implements Driver by refusing all operations without touching system networking.
type Unsupported struct{}

// RequireSupported rejects an unavailable driver before callers perform platform side effects.
func RequireSupported(driver Driver) error {
	switch driver.(type) {
	case nil, Unsupported, *Unsupported:
		return ErrUnsupported
	}
	return nil
}

// EnsureAbsent cannot confirm interface state without a platform-specific driver.
func (Unsupported) EnsureAbsent(context.Context, string) error { return ErrUnsupported }

// Start refuses to create a userspace daemon or interface without a verified platform driver.
func (Unsupported) Start(context.Context, string) (Reader, func(), error) {
	return nil, nil, ErrUnsupported
}

// Configure refuses to write an interface configuration without a verified platform driver.
func (Unsupported) Configure(context.Context, string, string) error { return ErrUnsupported }

// Activate refuses to change interface state without a verified platform driver.
func (Unsupported) Activate(context.Context, string) error { return ErrUnsupported }

// Address refuses to assign addresses without a verified platform driver.
func (Unsupported) Address(context.Context, string, string) error { return ErrUnsupported }

// Keepalive refuses to change peer settings without a verified platform driver.
func (Unsupported) Keepalive(context.Context, string, string, string) error { return ErrUnsupported }

// Endpoint refuses to change peer endpoints without a verified platform driver.
func (Unsupported) Endpoint(context.Context, string, string, string) error { return ErrUnsupported }

// Observe cannot read runtime state without a verified platform driver.
func (Unsupported) Observe(context.Context, Query, string) ([]byte, error) {
	return nil, ErrUnsupported
}

// Delete refuses to delete an interface without a verified platform driver.
func (Unsupported) Delete(context.Context, string) error { return ErrUnsupported }
