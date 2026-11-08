//go:build !keenetic

package controller

import "os"

// validAWGHealthMode accepts the group-readable heartbeat mode used by Linux services.
func validAWGHealthMode(mode os.FileMode) bool {
	return mode == 0640
}
