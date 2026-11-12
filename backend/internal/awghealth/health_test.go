package awghealth

import (
	"testing"
	"time"
)

// TestValidRecordFreshness rejects wrong, expired, future-dated and failed records while accepting the grace window.
func TestValidRecordFreshness(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	base := record{ID: "7f02067a-ca17-4c38-ae26-7c7fb21ca06a", UpdatedAt: now.Add(-time.Second), Status: "ready"}
	if !validRecord(base, base.ID, now) {
		t.Fatal("fresh valid record rejected")
	}
	base.UpdatedAt = now.Add(-maxAge + time.Second)
	if !validRecord(base, base.ID, now) {
		t.Fatal("heartbeat inside the grace window was rejected")
	}
	for _, candidate := range []record{
		{ID: "ca17", UpdatedAt: now, Status: "ready"},
		{ID: base.ID, UpdatedAt: now.Add(-maxAge - time.Second), Status: "ready"},
		{ID: base.ID, UpdatedAt: now.Add(2 * time.Second), Status: "ready"},
		{ID: base.ID, UpdatedAt: now, Status: "failed"},
		{ID: base.ID, ActiveUnderlay: base.ID, UpdatedAt: now, Status: "ready"},
	} {
		if validRecord(candidate, base.ID, now) {
			t.Fatalf("invalid record accepted: %+v", candidate)
		}
	}
}
