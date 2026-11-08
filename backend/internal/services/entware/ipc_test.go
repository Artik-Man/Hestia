//go:build linux

package entware

import (
	"errors"
	"testing"

	"github.com/Artik-Man/Hestia/internal/services"
)

// TestPublicErrorIncludesOnlyFixedServiceRole ensures public errors expose the role name without IPC internals.
func TestPublicErrorIncludesOnlyFixedServiceRole(t *testing.T) {
	if got := publicError(errors.New("private command output"), serviceRole(services.Router)); got != "managed service operation failed: router" {
		t.Fatalf("publicError() = %q, want fixed router category", got)
	}
	if got := publicError(ErrUnavailable, serviceRole(services.Controller)); got != "managed service role unavailable: controller" {
		t.Fatalf("publicError() = %q, want fixed controller category", got)
	}
}
