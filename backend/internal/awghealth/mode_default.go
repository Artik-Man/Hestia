//go:build !keenetic

package awghealth

import "os"

// validMode accepts the group-readable heartbeat mode used by Linux services.
func validMode(mode os.FileMode) bool { return mode == 0640 }
