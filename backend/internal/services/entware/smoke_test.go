//go:build linux

package entware

import (
	"testing"

	"github.com/Artik-Man/Hestia/internal/routing"
)

// TestDecodeSnapshotAcceptsEmptyDenyGroup permits the initial Keenetic selector to route only to deny.
func TestDecodeSnapshotAcceptsEmptyDenyGroup(t *testing.T) {
	config, err := decodeSnapshot([]byte(`{"groups":[{"id":"default","exits":[]}],"lists":[],"healthy":{}}`))
	if err != nil {
		t.Fatalf("empty deny group was rejected: %v", err)
	}
	if target := expectedTarget(config.Groups[0], config.Healthy); target != "deny" {
		t.Fatalf("empty group should select deny, got %q", target)
	}
	state := selectorState{Type: "Selector", Now: "deny", All: []string{"deny"}}
	if !selectorMatches(state, routing.Group{ID: "default"}, "deny") {
		t.Fatal("empty deny group did not match its live selector")
	}
}

// TestQualityReportIsRequiredOnlyForHysteriaPaths avoids blocking unrelated routing edits on stale probe topology.
func TestQualityReportIsRequiredOnlyForHysteriaPaths(t *testing.T) {
	if qualityReportIsRequired(smokeConfig{}) {
		t.Fatal("AWG-free configuration unexpectedly requires a quality report")
	}
	config := smokeConfig{ConnectorKinds: map[string]string{"relay": "hysteria2"}}
	if !qualityReportIsRequired(config) {
		t.Fatal("Hysteria 2 configuration may not ignore missing or stale availability probes")
	}
}
