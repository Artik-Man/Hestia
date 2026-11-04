//go:build !linux

package observer

import (
	"errors"
	"syscall"
)

// bindDevice refuses unbound probes on systems without the supported Linux socket option.
func bindDevice(string) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("interface-bound observation requires Linux")
	}
}
