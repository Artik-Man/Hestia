package controller

import "testing"

// TestRelayWindow verifies initial activation, intermittent and consecutive loss, and delayed peer-confirmed recovery.
func TestRelayWindow(t *testing.T) {
	for _, observations := range [][]bool{
		{true, false, false, false},
		{true, false, true, true, false, true, true, false},
	} {
		var window relayWindow
		for i, success := range observations {
			window.observe(success)
			if window.available != (i != len(observations)-1) {
				t.Fatalf("availability at sample %d in %v: %v", i, observations, window.available)
			}
		}
		for i := 1; i <= 3; i++ {
			window.observe(true)
			if window.available != (i == 3) {
				t.Fatalf("recovery after %d probes", i)
			}
		}
	}
}
