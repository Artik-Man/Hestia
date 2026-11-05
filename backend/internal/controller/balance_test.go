package controller

import (
	"context"
	"encoding/json"
	"github.com/Artik-Man/Hestia/internal/observer"
	"github.com/Artik-Man/Hestia/internal/routing"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"testing"
)

// TestBalancedEvidenceRequiresDistinctAgreeingIPs checks duplicate protocols, losing opposite scopes and shared failure.
func TestBalancedEvidenceRequiresDistinctAgreeingIPs(t *testing.T) {
	s := observer.Settings{Connections: []observer.Connection{{ID: "a"}, {ID: "b"}}, MinSamples: 5, MarginPercent: 20}
	scope := func(ip, proto string, winsA, winsB int) observer.Report {
		return observer.Report{Target: observer.Target{Address: ip, Protocol: proto}, Samples: 10, Recommended: "b", Counts: map[string]observer.Counts{"a": {Sent: 10, Received: winsA}, "b": {Sent: 10, Received: winsB}}, Latest: map[string]observer.Probe{"a": {Status: observer.Received}, "b": {Status: observer.Received}}}
	}
	x := scope("192.0.2.1", "udp", 6, 10)
	y := scope("192.0.2.2", "udp", 6, 10)
	tests := []struct {
		name string
		a, b observer.Report
		want string
		vote int
	}{
		{"two witnesses", x, y, "qualifies", 2},
		{"same address twice", x, scope("192.0.2.1", "tcp", 6, 10), "no_quorum", 1},
		{"sticky recommendation on tie", scope("192.0.2.1", "udp", 10, 10), scope("192.0.2.2", "udp", 10, 10), "no_quorum", 0},
		{"shared failure", x, scope("192.0.2.2", "tcp", 0, 0), "shared_failure", 1},
		{"inconsistent targets", x, scope("192.0.2.2", "udp", 10, 6), "opposing_evidence", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			votes, reason := balanceVotes(s, []observer.Report{tt.a, tt.b}, "a", "b")
			if reason != tt.want || len(votes) != tt.vote {
				t.Fatalf("%v %s", votes, reason)
			}
		})
	}
	if votes, reason := balanceVotes(s, []observer.Report{x, y, scope("192.0.2.3", "udp", 0, 0), scope("192.0.2.3", "tcp", 10, 4)}, "a", "b"); reason != "qualifies" || len(votes) != 2 {
		t.Fatalf("unreachable third IP must abstain, not veto: %v %s", votes, reason)
	}

}

// TestBalanceUsesActualSelectorAndReadback proves reversal from an externally preselected exit and reports failed confirmation.
func TestBalanceUsesActualSelectorAndReadback(t *testing.T) {
	s := observer.Settings{Group: "fi", Connections: []observer.Connection{{ID: "a"}, {ID: "b"}}, MinSamples: 2, MarginPercent: 10}
	g := routing.Group{ID: "fi", Exits: []string{"a", "b"}}
	reports := []observer.Report{}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		reports = append(reports, observer.Report{Target: observer.Target{Address: ip, Protocol: "udp"}, Recommended: "b", Samples: 10, Counts: map[string]observer.Counts{"a": {Sent: 10, Received: 10}, "b": {Sent: 10, Received: 4}}, Latest: map[string]observer.Probe{"a": {Status: observer.Received}, "b": {Status: observer.Received}}})
	}
	for _, ignore := range []bool{false, true} {
		current := "b"
		writes := []string{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/proxies/fi" {
				t.Errorf("touched foreign selector: %s", r.URL.Path)
			}
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(selector{Type: "Selector", Now: current, All: []string{"b", "deny", "a"}})
				return
			}
			var req struct{ Name string }
			json.NewDecoder(r.Body).Decode(&req)
			writes = append(writes, req.Name)
			if !ignore {
				current = req.Name
			}
			w.WriteHeader(204)
		}))
		st := &balanceState{}
		first, err := st.balance(context.Background(), server.Client(), server.URL, s, g, reports, 2)
		if err != nil || first.Reason != "confirming" || first.Applied != "b" || len(writes) != 0 {
			t.Fatalf("premature change: %+v %v", first, err)
		}
		result, err := st.balance(context.Background(), server.Client(), server.URL, s, g, reports, 2)
		if !slices.Equal(writes, []string{"a"}) || result.Current != "b" || result.Recommended != "a" {
			t.Fatalf("expected measured change b->a: %+v %v", result, err)
		}
		if ignore {
			if err == nil || result.Applied != "unknown" {
				t.Fatalf("unconfirmed write accepted: %+v %v", result, err)
			}
		} else if err != nil || result.Applied != "a" || result.Reason != "better_delivery" {
			t.Fatalf("actual change missing: %+v %v", result, err)
		}
		current = "deny"
		closed, err := st.balance(context.Background(), server.Client(), server.URL, s, g, reports, 1)
		if err != nil || closed.Applied != "deny" || closed.Reason != "deny_active" || len(writes) != 1 {
			t.Fatalf("deny overridden: %+v %v", closed, err)
		}
		server.Close()
	}
}

// TestBalanceWriterExcludesSnapshot verifies the conventional writer refuses the group's lock before contacting sing-box.
func TestBalanceWriterExcludesSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux abstract namespace socket")
	}
	const group = "hestia-test-balance-lock"
	lease, err := groupLock(group)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Errorf("unexpected request %s", r.URL.Path) }))
	defer server.Close()
	if _, err := ownedReconcile(context.Background(), server.Client(), server.URL, routing.Group{ID: group, Exits: []string{"a", "b"}}, "a"); err == nil {
		t.Fatal("concurrent snapshot writer admitted")
	}
}
