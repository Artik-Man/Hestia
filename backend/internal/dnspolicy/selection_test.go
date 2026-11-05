package dnspolicy

import (
	"slices"
	"testing"
)

// TestSelectWarmDomains verifies the automatic threshold, independent exclusions and deduplicated manual overlap.
func TestSelectWarmDomains(t *testing.T) {
	counts := map[string]int{"both.example": 5, "blocked.example": 9, "manual.example": 7, "quiet.example": 4}
	manual := []string{"both.example", "manual.example", "cold.example"}
	excluded := []string{"blocked.example", "manual.example", "future.example"}
	selected, err := SelectWarmDomains(5, counts, manual, excluded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(selected.Automatic, []string{"both.example"}) ||
		!slices.Equal(selected.Effective, []string{"both.example", "cold.example", "manual.example"}) {
		t.Fatalf("unexpected warm selection: %+v", selected)
	}
}

// TestSelectWarmDomainsReevaluates checks automatic reentry after unblocking and removal on declining demand.
func TestSelectWarmDomainsReevaluates(t *testing.T) {
	counts := map[string]int{"site.example": 5}
	selected, err := SelectWarmDomains(5, counts, nil, nil)
	if err != nil || !slices.Equal(selected.Effective, []string{"site.example"}) {
		t.Fatalf("eligible name after unblock: %+v, %v", selected, err)
	}
	counts["site.example"]--
	selected, err = SelectWarmDomains(5, counts, nil, nil)
	if err != nil || len(selected.Effective) != 0 {
		t.Fatalf("expired demand without a manual pin: %+v, %v", selected, err)
	}
}

// TestSelectWarmDomainsInvalidThreshold verifies a misconfigured policy cannot schedule domains.
func TestSelectWarmDomainsInvalidThreshold(t *testing.T) {
	if _, err := SelectWarmDomains(0, nil, nil, nil); err == nil {
		t.Fatal("expected invalid threshold to fail")
	}
}
