//go:build linux && keenetic

package awg

import "os"

// healthMarkerOwnership keeps Keenetic health metadata root-only without requiring a host-managed group.
func healthMarkerOwnership() (int, int, os.FileMode, error) {
	return 0, 0, 0600, nil
}
