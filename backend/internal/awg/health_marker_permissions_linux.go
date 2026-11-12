//go:build linux && !keenetic

package awg

import (
	"errors"
	"os"
	"os/user"
	"strconv"
)

// healthMarkerOwnership returns the Linux service group required by the panel to read health metadata.
func healthMarkerOwnership() (int, int, os.FileMode, error) {
	group, err := user.LookupGroup("hestia-snapshot")
	if err != nil {
		return 0, 0, 0, errors.New("cannot resolve Hestia snapshot group")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil {
		return 0, 0, 0, errors.New("cannot resolve Hestia snapshot group")
	}
	return 0, gid, 0640, nil
}
