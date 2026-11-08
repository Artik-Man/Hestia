//go:build keenetic

package controller

import (
	"os"
	"testing"
)

// TestKeeneticAWGHealthModeRequiresPrivateRootFile accepts only the target's root-only heartbeat mode.
func TestKeeneticAWGHealthModeRequiresPrivateRootFile(t *testing.T) {
	if !validAWGHealthMode(0600) {
		t.Fatal("Keenetic root-only heartbeat mode was rejected")
	}
	for _, mode := range []os.FileMode{0640, 0644, 0660} {
		if validAWGHealthMode(mode) {
			t.Fatalf("unsafe or non-Keenetic heartbeat mode %04o was accepted", mode)
		}
	}
}
