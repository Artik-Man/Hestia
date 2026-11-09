//go:build keenetic

package awghealth

import "os"

// validMode accepts the private root-only heartbeat mode used by Keenetic services.
func validMode(mode os.FileMode) bool { return mode == 0600 }
