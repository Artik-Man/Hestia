package controller

import (
	"testing"

	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// TestQualitySelectionKeepsAvailabilityAndEvidence distinguishes equal, partial and corroborated scores.
func TestQualitySelectionKeepsAvailabilityAndEvidence(t *testing.T) {
	group := routing.Group{ID: "group", Exits: []string{"one", "two"}}
	score := func(value float64, second string) quality.Result {
		return quality.Result{Overall: &value, Checks: []quality.CheckResult{{Protocol: "UDP", Targets: []quality.TargetResult{
			{Target: "1.1.1.1:53", Samples: 3, Score: &value}, {Target: second, Samples: 3, Score: &value},
		}}}}
	}
	for _, test := range []struct {
		name          string
		first, second quality.Result
		current, want string
		available     bool
	}{
		{"higher score and two distinct targets", score(50, "8.8.8.8:53"), score(100, "8.8.8.8:53"), "one", "two", true},
		{"one distinct IP", score(50, "1.1.1.1:443"), score(100, "1.1.1.1:443"), "one", "one", true},
		{"current has incomplete data", quality.Result{}, score(100, "8.8.8.8:53"), "one", "one", true},
		{"tie retains live selection", score(100, "8.8.8.8:53"), score(100, "8.8.8.8:53"), "two", "two", true},
		{"unavailable current yields to available path", score(100, "8.8.8.8:53"), quality.Result{}, "one", "two", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			order := qualityOrder(group, map[string]bool{"one": test.available, "two": true}, test.current, map[string]quality.Result{"one": test.first, "two": test.second})
			if got := qualityTarget(order, test.current); got != test.want {
				t.Fatalf("selected %q, want %q", got, test.want)
			}
		})
	}
}

// TestICMPQualityEvidence counts distinct ICMP addresses and deduplicates a shared ICMP/TCP destination.
func TestICMPQualityEvidence(t *testing.T) {
	result := func(score float64, secondIP string) quality.Result {
		return quality.Result{Checks: []quality.CheckResult{
			{Protocol: quality.ICMP, Targets: []quality.TargetResult{
				{Target: "1.1.1.1", Samples: 3, Score: &score},
				{Target: secondIP, Samples: 3, Score: &score},
			}},
			{Protocol: quality.TCP, Targets: []quality.TargetResult{{Target: "1.1.1.1:443", Samples: 3, Score: &score}}},
		}}
	}
	if !corroborated(result(100, "8.8.8.8"), result(50, "8.8.8.8")) {
		t.Fatal("two improving ICMP targets did not qualify")
	}
	if corroborated(result(100, "::ffff:1.1.1.1"), result(50, "::ffff:1.1.1.1")) {
		t.Fatal("one IP counted as independent targets")
	}
}
