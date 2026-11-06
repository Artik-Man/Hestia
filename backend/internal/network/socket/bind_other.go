//go:build !linux

package socket

import (
	"errors"
	"syscall"
)

// Platform refuses Linux socket confinement on unsupported hosts.
type Platform struct{}

// Bind fails before any packet can leave through ordinary host routing.
func (Platform) Bind(p Path) Control {
	return func(string, string, syscall.RawConn) error {
		if p.Mode == DeviceOnly {
			return errors.New("interface-bound observation requires Linux")
		}
		return errors.New("interface-bound quality probes require Linux")
	}
}
