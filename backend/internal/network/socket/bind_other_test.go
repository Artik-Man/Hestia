//go:build !linux

package socket

import "testing"

// TestUnsupportedBindingFailsClosed rejects callbacks without touching an unbound socket.
func TestUnsupportedBindingFailsClosed(t *testing.T) {
	for _, mode := range []Mode{DeviceOnly, DeviceThenMark, MarkAndDevice} {
		if err := (Platform{}).Bind(Path{Device: "eth0", Mark: 514, Mode: mode})("udp4", "192.0.2.1:53", nil); err == nil {
			t.Fatal("unsupported binding accepted")
		}
	}
}
