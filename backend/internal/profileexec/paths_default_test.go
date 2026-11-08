//go:build !keenetic

package profileexec

import (
	"context"
	"reflect"
	"testing"
)

// TestCheckBackendUsesStandardBinary verifies the default Linux backend validator command.
func TestCheckBackendUsesStandardBinary(t *testing.T) {
	called := false
	adapter := Installed{Run: func(_ context.Context, name string, args ...string) error {
		called = true
		if name != Backend || !reflect.DeepEqual(args, []string{"check", "-c", "stage/sing-box.json"}) {
			t.Fatalf("backend check got %s %v", name, args)
		}
		return nil
	}}
	if err := adapter.CheckBackend(context.Background(), "stage/sing-box.json"); err != nil || !called {
		t.Fatalf("backend validation command failed: %v", err)
	}
}
