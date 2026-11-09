//go:build keenetic

package awghealth

import (
	"os"
	"testing"
)

// TestKeeneticModeRequiresPrivateRootFile accepts only the target's root-only heartbeat mode.
func TestKeeneticModeRequiresPrivateRootFile(t *testing.T) {
	if !validMode(0600) {
		t.Fatal("Keenetic root-only heartbeat mode was rejected")
	}
	for _, mode := range []os.FileMode{0640, 0644, 0660} {
		if validMode(mode) {
			t.Fatalf("unsafe or non-Keenetic heartbeat mode %04o was accepted", mode)
		}
	}
}
