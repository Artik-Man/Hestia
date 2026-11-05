package observer

import (
	"testing"
	"time"
)

// TestScopedLossAndRecovery verifies scoped loss, sample expiry, and holding the selected path on equality.
func TestScopedLossAndRecovery(t *testing.T) {
	connections := []Connection{{ID: "FI1", Interface: "fi1"}, {ID: "FI2", Interface: "fi2"}}
	settings := Settings{Connections: connections, Window: time.Minute, MinSamples: 2, MarginPercent: 20}
	at := time.Unix(1, 0)
	h := newHistory(settings, Target{Address: "203.0.113.1", Port: 19091, Protocol: "udp"})
	bad := []Probe{{Status: Lost}, {Status: Received}}
	if got := h.observe(at, bad); got.Recommended != "FI1" || got.Reason != "insufficient_samples" {
		t.Fatalf("early switch %+v", got)
	}
	if got := h.observe(at.Add(time.Second), bad); got.Recommended != "FI2" || got.Counts["FI1"].Lost != 2 {
		t.Fatalf("did not switch %+v", got)
	}
	ok := []Probe{{Status: Received}, {Status: Received}}
	h.observe(at.Add(61*time.Second), ok)
	if got := h.observe(at.Add(62*time.Second), ok); got.Current != "FI2" || got.Recommended != "FI2" || got.Samples != 2 || got.Counts["FI1"].Lost != 0 {
		t.Fatalf("expiry or tie failed %+v", got)
	}
	// The same IP over TCP has independent state.
	tcp := newHistory(settings, Target{Address: "203.0.113.1", Port: 19091, Protocol: "tcp"})
	if got := tcp.observe(at, ok); got.Recommended != "FI1" {
		t.Fatalf("cross-scope leak %+v", got)
	}
}

// TestIncompletePairedRound excludes the entire round if one socket could not bind to its interface.
func TestIncompletePairedRound(t *testing.T) {
	h := newHistory(Settings{Connections: []Connection{{ID: "FI1"}, {ID: "FI2"}}, Window: time.Hour, MinSamples: 1, MarginPercent: 10}, Target{})
	got := h.observe(time.Now(), []Probe{{Status: LocalError}, {Status: Received}})
	if got.Samples != 0 || got.Counts["FI2"].Sent != 0 || got.Recommended != "FI1" || got.Reason != "local_error" {
		t.Fatalf("biased evidence %+v", got)
	}
}
