//go:build keenetic

package controller

import "os"

// validAWGHealthMode accepts the private root-only heartbeat mode used by Keenetic services.
func validAWGHealthMode(mode os.FileMode) bool {
	return mode == 0600
}
