package observer

import "github.com/Artik-Man/Hestia/internal/network/socket"

// bindDevice delegates socket confinement to the installed platform adapter and fails closed on errors.
func bindDevice(iface string) socket.Control {
	return socket.Platform{}.Bind(socket.Path{Device: iface, Mode: socket.DeviceOnly})
}
