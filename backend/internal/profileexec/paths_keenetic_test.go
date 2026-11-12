//go:build keenetic

package profileexec

import (
	"context"
	"reflect"
	"testing"
)

// TestCheckBackendUsesEntwareLoader verifies Keenetic's loader and explicit shared-library path.
func TestCheckBackendUsesEntwareLoader(t *testing.T) {
	called := false
	adapter := Installed{Run: func(_ context.Context, name string, args ...string) error {
		called = true
		want := []string{"--library-path", "/opt/lib:/opt/lib/hestia", Backend, "check", "-c", "stage/sing-box.json"}
		if name != "/opt/lib/ld-linux-aarch64.so.1" || !reflect.DeepEqual(args, want) {
			t.Fatalf("backend check got %s %v", name, args)
		}
		return nil
	}}
	if err := adapter.CheckBackend(context.Background(), "stage/sing-box.json"); err != nil || !called {
		t.Fatalf("backend validation command failed: %v", err)
	}
}
