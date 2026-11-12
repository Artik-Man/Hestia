//go:build linux && keenetic

package awgruntime

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestEntwareParentIsProtected accepts root-owned private directories and root-owned sticky temporary directories.
func TestEntwareParentIsProtected(t *testing.T) {
	tests := []struct {
		name string
		uid  uint32
		mode uint32
		want bool
	}{
		{name: "private root directory", uid: 0, mode: 0755, want: true},
		{name: "root sticky temporary directory", uid: 0, mode: 01777, want: true},
		{name: "writable without sticky bit", uid: 0, mode: 0777, want: false},
		{name: "non-root sticky directory", uid: 1000, mode: 01777, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := entwareParentIsProtected(test.uid, test.mode); got != test.want {
				t.Fatalf("entwareParentIsProtected(%d, %#o) = %t, want %t", test.uid, test.mode, got, test.want)
			}
		})
	}
}

// TestValidKeepalive accepts scalar and ranged AmneziaWG keepalive settings and rejects malformed ranges.
func TestValidKeepalive(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{value: "0", want: true},
		{value: "25", want: true},
		{value: "25-35", want: true},
		{value: "0-65535", want: true},
		{value: "35-25", want: false},
		{value: "025", want: false},
		{value: "25-", want: false},
		{value: "25-35-45", want: false},
		{value: "65536", want: false},
		{value: "", want: false},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			if got := validKeepalive(test.value); got != test.want {
				t.Fatalf("validKeepalive(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

// TestClearStaleEntwareUAPISocketRemovesOnlyInactiveSockets prevents stale runtime sockets from blocking retries.
func TestClearStaleEntwareUAPISocketRemovesOnlyInactiveSockets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "awg0.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	unixListener := listener.(*net.UnixListener)
	unixListener.SetUnlinkOnClose(false)
	if err := unixListener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := clearStaleEntwareUAPISocket(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket remains: %v", err)
	}

	active, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err := clearStaleEntwareUAPISocket(path); err == nil {
		t.Fatal("active UAPI socket was removed")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("active socket path was removed: %v", err)
	}
}
