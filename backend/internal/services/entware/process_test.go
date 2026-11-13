//go:build linux

package entware

import (
	"slices"
	"testing"

	"github.com/Artik-Man/Hestia/internal/services"
)

// TestManagedServiceEnvironmentLimitsGoMemoryForRouter verifies only the sing-box router receives the requested Go GC limits.
func TestManagedServiceEnvironmentLimitsGoMemoryForRouter(t *testing.T) {
	router := managedServiceEnvironment(services.Service{Kind: services.Router})
	if !slices.Contains(router, "GOMEMLIMIT=140MiB") || !slices.Contains(router, "GOGC=100") {
		t.Fatalf("router environment lacks memory limits: %v", router)
	}
	controller := managedServiceEnvironment(services.Service{Kind: services.Controller})
	if slices.Contains(controller, "GOMEMLIMIT=140MiB") || slices.Contains(controller, "GOGC=100") {
		t.Fatalf("controller unexpectedly received router memory limits: %v", controller)
	}
}
