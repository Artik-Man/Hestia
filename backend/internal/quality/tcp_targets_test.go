package quality

import (
	"context"
	"slices"
	"testing"
)

// TestTCPInputAddresses verifies default ports, explicit IPv6 ports and rejection of invalid literal targets before saving.
func TestTCPInputAddresses(t *testing.T) {
	check := Check{Protocol: TCP, Targets: []string{"8.8.8.8", "2606:4700:4700::1111", "[2606:4700:4700::1001]:8443"}}
	want := []string{"8.8.8.8:443", "[2606:4700:4700::1111]:443", "[2606:4700:4700::1001]:8443"}
	if err := check.NormalizeTCPInput(context.Background(), ""); err != nil || !slices.Equal(check.Targets, want) {
		t.Fatalf("targets %v, error %v", check.Targets, err)
	}
	for _, bad := range []string{"127.0.0.1", "8.8.8.8:", "8.8.8.8:0", "8.8.8.8:65536", "8.8.8.8:https", "a..example", "[example.org]:443"} {
		check.Targets = []string{"1.1.1.1", bad}
		if err := check.NormalizeTCPInput(context.Background(), ""); err == nil || check.Targets[0] != "1.1.1.1" {
			t.Fatalf("invalid input %q: targets %v, error %v", bad, check.Targets, err)
		}
	}
}
