//go:build !keenetic

package binding

import "testing"

// TestDefaultPlatformHasNoKeeneticUnderlay prevents leaking the router-specific candidate into Linux builds.
func TestDefaultPlatformHasNoKeeneticUnderlay(t *testing.T) {
	if len(platformUnderlayCandidates()) != 0 {
		t.Fatal("Keenetic underlay leaked into the default platform")
	}
	if ensurePlatformUnderlay(&storedProfile{}, "") == nil {
		t.Fatal("default platform accepted a Keenetic-only underlay")
	}
}
