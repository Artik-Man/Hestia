//go:build !linux

package quality

import (
	"errors"
	"syscall"
)

// bindPath refuses ordinary routing on hosts without Linux route marks and interface binding.
func bindPath(Path) func(string, string, syscall.RawConn) error {
	return func(string, string, syscall.RawConn) error {
		return errors.New("interface-bound quality probes require Linux")
	}
}
