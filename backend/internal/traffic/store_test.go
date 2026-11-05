package traffic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestJournalPages verifies stable newest-first paging across concurrent appends, independent filters and restart.
func TestJournalPages(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	start := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Hour)
	events := make([]TrafficEvent, 621)
	for i := range events {
		events[i] = TrafficEvent{Time: start.Add(time.Duration(i) * time.Second), Protocol: "TCP", Address: "2001:db8::12", Port: 443, Kind: Unconfirmed, Connection: "fi"}
		if i%2 == 0 {
			events[i].Protocol = "UDP"
			events[i].Domain = "API.Example.org"
		}
	}
	events[13].Kind = Blocked
	events[13].BlockReason = "reject"
	events[13].Connection = ""
	events[12].Kind = Observed
	events[12].NetworkInterface = "ppp0"
	events[12].Connection = "ru"
	if err = store.AppendBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	first, err := store.Page(ctx, Query{Limit: 500})
	if err != nil || first.Total != 621 || len(first.Events) != 500 || first.Events[0].ID != "621" {
		t.Fatalf("first page: total=%d rows=%d err=%v", first.Total, len(first.Events), err)
	}
	if err = store.Append(ctx, events[620]); err != nil {
		t.Fatal(err)
	}
	next, err := store.Page(ctx, Query{Limit: 500, Offset: 500, Snapshot: first.Snapshot})
	if err != nil || next.Total != 621 || len(next.Events) != 121 || next.Events[0].ID != "121" {
		t.Fatalf("next: %+v %v", next, err)
	}
	filtered, err := store.Page(ctx, Query{Limit: 500, Text: "AMPLE", Output: ConnectionFilter + "fi", Protocol: "UDP", From: start, Until: start.Add(time.Minute)})
	if err != nil || filtered.Total != 30 || !slices.Equal(filtered.Outputs, []string{"fi", "ru"}) {
		t.Fatalf("filtered total=%d outputs=%v err=%v", filtered.Total, filtered.Outputs, err)
	}
	blocked, err := store.Page(ctx, Query{Limit: 10, Text: "db8::", Protocol: "TCP", Output: Blocked})
	if err != nil || len(blocked.Events) != 1 || blocked.Events[0].BlockReason != "reject" {
		t.Fatalf("blocked: %+v %v", blocked, err)
	}
	if err = store.RecordLoss(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Page(ctx, Query{Limit: 1})
	if err != nil || page.Total != 622 || page.SourceAvailable || page.Lost != 3 {
		t.Fatalf("reopened: %+v %v", page, err)
	}
}

// TestJournalBounds verifies atomic policy replacement, age cleanup and actual on-disk size after tightening the quota.
func TestJournalBounds(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := s.Settings(ctx)
	if err != nil || cfg != (TrafficSettings{MaxMB: 1024, RetentionHours: 24}) {
		t.Fatalf("default settings: %+v %v", cfg, err)
	}
	now := time.Now().UTC()
	events := make([]TrafficEvent, 800)
	for i := range events {
		events[i] = TrafficEvent{Time: now.Add(-time.Duration(800-i) * time.Second), Protocol: "TCP", Address: "192.0.2.9", Port: 443, Kind: Unconfirmed, Reason: strings.Repeat("x", 3200)}
	}
	if err = s.AppendBatch(ctx, events); err != nil {
		t.Fatal(err)
	}
	settings := TrafficSettings{MaxMB: 1, RetentionHours: 1}
	if err = s.SaveSettings(ctx, TrafficSettingsChange{Expected: cfg, Proposed: settings}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "journal.db"))
	if err != nil || info.Size() > 1<<20 {
		t.Fatalf("disk size %v %v", info, err)
	}
	p, err := s.Page(ctx, Query{Limit: 1})
	if err != nil || p.Total == 0 || p.Total >= 800 || p.Events[0].ID != "800" {
		t.Fatalf("quota: %+v %v", p, err)
	}
	old := events[0]
	old.Time = now.Add(-2 * time.Hour)
	if err = s.Append(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSettings(ctx, TrafficSettingsChange{Expected: settings, Proposed: TrafficSettings{MaxMB: 1, RetentionHours: 2}}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow("SELECT COUNT(*) FROM events WHERE seq=801").Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired row retained: %d %v", count, err)
	}
	if err = s.SaveSettings(ctx, TrafficSettingsChange{Expected: settings, Proposed: TrafficSettings{MaxMB: 0, RetentionHours: 1}}); !errors.Is(err, ErrQuery) {
		t.Fatalf("invalid update: %v", err)
	}
}

// TestJournalInterruptionUpgrade preserves history in an older journal and keeps stream gaps visible after reconnect and restart.
func TestJournalInterruptionUpgrade(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DROP TABLE source_state"); err != nil {
		t.Fatal(err)
	}
	event := TrafficEvent{Time: time.Now().UTC(), Protocol: "TCP", Kind: Unconfirmed, Address: "192.0.2.5", Port: 443}
	if err = s.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Page(ctx, Query{Limit: 1})
	if err != nil || p.LastInterruption != nil || p.Total != 1 {
		t.Fatalf("legacy migration: %+v %v", p, err)
	}
	gap := time.Now().UTC().Truncate(time.Millisecond)
	if err = s.RecordInterruption(ctx, gap); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetAvailable(true)
	p, err = s.Page(ctx, Query{Limit: 1})
	if err != nil || p.LastInterruption == nil || !p.LastInterruption.Equal(gap) || !p.SourceAvailable || p.Lost != 0 || p.Total != 1 {
		t.Fatalf("recovered gap: %+v %v", p, err)
	}
}
