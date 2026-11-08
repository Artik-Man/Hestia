//go:build linux && keenetic

package awg

import "testing"

// TestKeeneticHealthMarkerOwnershipUsesPrivateRootFile avoids relying on a host-managed snapshot group.
func TestKeeneticHealthMarkerOwnershipUsesPrivateRootFile(t *testing.T) {
	uid, gid, mode, err := healthMarkerOwnership()
	if err != nil || uid != 0 || gid != 0 || mode.Perm() != 0600 {
		t.Fatalf("healthMarkerOwnership() = (%d, %d, %#o, %v), want root:root 0600", uid, gid, mode.Perm(), err)
	}
}
