//go:build linux

package quality

import "syscall"

// bindPath applies the interface and, where configured, the route mark before the first packet leaves the socket.
func bindPath(p Path) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, p.Device)
			if err == nil && p.Mark != 0 {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, p.Mark)
			}
		}); e != nil {
			return e
		}
		return err
	}
}
