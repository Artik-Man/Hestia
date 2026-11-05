package awg

import (
	"testing"
	"time"
)

// TestUnderlayPriorityAndLoss requires real hysteresis before falling back or reusing a recovered preferred path.
func TestUnderlayPriorityAndLoss(t *testing.T) {
	paths := make([]pathQuality, 2)
	now := time.Now()
	for i := range paths {
		paths[i].observe(true)
	}
	for _, ok := range []bool{false, true, false, true, true, true, false} {
		paths[0].observe(ok)
	}
	if got := preferredUnderlay(paths, now); got != 1 {
		t.Fatalf("intermittent loss did not demote preferred path: %d", got)
	}
	for i := 0; i < 2; i++ {
		paths[0].observe(true)
	}
	if preferredUnderlay(paths, now) != 1 {
		t.Fatal("preferred path recovered prematurely")
	}
	paths[0].observe(true)
	if preferredUnderlay(paths, now) != 0 {
		t.Fatal("recovered preferred path was not restored")
	}
}

// TestPeerSpecificBackoff protects the third path against repeated preferred-path trials when only the peer UDP port is blocked.
func TestPeerSpecificBackoff(t *testing.T) {
	now := time.Now()
	paths := make([]pathQuality, 3)
	for i := range paths {
		paths[i].observe(true)
	}
	paths[0].quarantine(now)
	paths[1].quarantine(now)
	for range 10 {
		paths[0].observe(true)
		paths[1].observe(true)
	}
	if preferredUnderlay(paths, now.Add(29*time.Second)) != 2 {
		t.Fatal("unrelated HTTPS success displaced the verified fallback")
	}
	later := now.Add(30 * time.Second)
	paths[0].quarantine(later)
	if !paths[0].retryAfter.Equal(later.Add(time.Minute)) {
		t.Fatal("consecutive peer-specific failures did not back off")
	}
	for range 3 {
		paths[0].confirmPeer()
	}
	if paths[0].backoff != 0 {
		t.Fatal("confirmed peer did not clear retry history")
	}
}

// TestActivationTriesAllDistinctCandidates avoids starvation when early cooldowns expire during long ordered lists.
func TestActivationTriesAllDistinctCandidates(t *testing.T) {
	now := time.Now()
	paths := make([]pathQuality, 12)
	for i := range paths {
		paths[i].observe(true)
	}
	for want := range paths {
		at := now.Add(time.Duration(want) * 8 * time.Second)
		if got := activationUnderlay(paths, at); got != want {
			t.Fatalf("candidate %d selected before untested %d", got, want)
		}
		paths[want].quarantine(at)
	}
}
