//go:build linux

package socket

import (
	"syscall"
)

// Platform binds sockets using Linux interface and policy-mark options.
type Platform struct{}

// Bind applies the specified options in the established order and propagates every failure.
func (Platform) Bind(p Path) Control {
	return func(_, _ string, raw syscall.RawConn) error {
		var result error
		if err := raw.Control(func(fd uintptr) {
			device := func() error {
				return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, p.Device)
			}
			mark := func() error { return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, p.Mark) }
			result = applyOptions(p, device, mark)
		}); err != nil {
			return err
		}
		return result
	}
}
