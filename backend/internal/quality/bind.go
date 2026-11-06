package quality

import "github.com/Artik-Man/Hestia/internal/network/socket"

// bindPath delegates socket confinement to the installed platform adapter and fails closed on errors.
func bindPath(p Path) socket.Control {
	return socket.Platform{}.Bind(socket.Path{Device: p.Device, Mark: p.Mark, Mode: socket.DeviceThenMark})
}
