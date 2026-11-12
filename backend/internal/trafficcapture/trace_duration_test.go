package trafficcapture

import (
	"testing"
	"time"
)

// TestBoundedTraceDurationClampsCleanupOvershootAtTheRequestedLimit verifies the reported window excludes cleanup overhead.
func TestBoundedTraceDurationClampsCleanupOvershootAtTheRequestedLimit(t *testing.T) {
	if got := boundedTraceDuration(15*time.Second+250*time.Millisecond, 15); got != 15000 {
		t.Fatalf("15-second duration with cleanup overshoot = %d ms, want 15000", got)
	}
	if got := boundedTraceDuration(6*time.Second+150*time.Millisecond, 15); got != 6150 {
		t.Fatalf("short trace duration = %d ms, want 6150", got)
	}
}
