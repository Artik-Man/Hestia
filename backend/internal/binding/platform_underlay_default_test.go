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

// TestDefaultPlatformChannelRolesPreserveLinuxEndpoints checks the Linux input/output metadata used by the panel.
func TestDefaultPlatformChannelRolesPreserveLinuxEndpoints(t *testing.T) {
	if got := PlatformChannelRole("wg-keenetic"); got != "input" {
		t.Fatalf("Linux input role = %q, want input", got)
	}
	if got := PlatformChannelRole("keenetic-direct"); got != "output" {
		t.Fatalf("Linux output role = %q, want output", got)
	}
}
