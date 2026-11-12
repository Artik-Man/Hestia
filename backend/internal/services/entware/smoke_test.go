//go:build linux

package entware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/routing"
)

// TestSelectorConvergenceHasBoundedStartupGrace gives a loaded Keenetic controller time to publish fresh selector state.
func TestSelectorConvergenceHasBoundedStartupGrace(t *testing.T) {
	if selectorConvergenceTimeout != 30*time.Second {
		t.Fatalf("selector convergence timeout = %s, want 30s", selectorConvergenceTimeout)
	}
}

// TestEffectiveHealthRequiresFreshAWGHeartbeat keeps configured AWG exits unavailable until their runtime heartbeat is fresh.
func TestEffectiveHealthRequiresFreshAWGHeartbeat(t *testing.T) {
	config := smokeConfig{
		Groups:         []routing.Group{{ID: "amnezia", Exits: []string{"awg-connector"}}},
		Healthy:        map[string]bool{"awg-connector": true},
		ConnectorKinds: map[string]string{"awg-connector": "awg"},
	}
	for _, tc := range []struct {
		name  string
		ready func(string) bool
		want  bool
	}{
		{name: "stale heartbeat", ready: func(string) bool { return false }, want: false},
		{name: "fresh heartbeat", ready: func(string) bool { return true }, want: true},
		{name: "missing heartbeat reader", ready: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := effectiveHealth(config, backendConfig{}, tc.ready)
			if health["awg-connector"] != tc.want {
				t.Fatalf("AWG health = %v, want %v", health["awg-connector"], tc.want)
			}
		})
	}
}

// TestWaitForLiveSelectorsAllowsControllerConvergence tolerates a brief selector transition while requiring the configured state to become live.
func TestWaitForLiveSelectorsAllowsControllerConvergence(t *testing.T) {
	otherReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := selectorState{Type: "Selector"}
		switch r.URL.Path {
		case "/proxies/default":
			state.Now, state.All = "keenetic-uplink", []string{"keenetic-uplink", "deny"}
		case "/proxies/other":
			otherReads++
			state.All = []string{"exit-1", "deny"}
			state.Now = "deny"
			if otherReads >= 3 {
				state.Now = "exit-1"
			}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	config := smokeConfig{Groups: []routing.Group{
		{ID: "default", Exits: []string{"keenetic-uplink"}},
		{ID: "other", Exits: []string{"exit-1"}},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	health := map[string]bool{"keenetic-uplink": true, "exit-1": true}
	if err := waitForLiveSelectors(ctx, client, server.URL, config, health, nil); err != nil {
		t.Fatalf("brief selector transition prevented smoke confirmation: %v", err)
	}
	if otherReads < 3 {
		t.Fatalf("selector was accepted before convergence: reads=%d", otherReads)
	}
}

// TestWaitForSelectorTargetsTracksQualityChanges waits for selectors and controller events to agree on the latest quality target.
func TestWaitForSelectorTargetsTracksQualityChanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(selectorState{Type: "Selector", Now: "exit-1", All: []string{"exit-1", "deny"}})
	}))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	groups := []routing.Group{{ID: "other", Exits: []string{"exit-1"}}}
	expectedReads, confirmations := 0, 0
	expected := func() (map[string]string, error) {
		expectedReads++
		if expectedReads == 1 {
			return map[string]string{"other": "deny"}, nil
		}
		return map[string]string{"other": "exit-1"}, nil
	}
	confirmed := func(targets map[string]string) bool {
		confirmations++
		return confirmations > 1 && targets["other"] == "exit-1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := waitForSelectorTargets(ctx, client, server.URL, groups, expected, confirmed); err != nil {
		t.Fatalf("latest quality target and controller event did not converge: %v", err)
	}
	if expectedReads < 2 || confirmations < 2 {
		t.Fatalf("smoke accepted stale evidence: expected reads=%d confirmations=%d", expectedReads, confirmations)
	}
}

// TestWaitForLiveSelectorsRejectsPersistentDrift keeps the smoke gate closed when a selector never reaches the installed target.
func TestWaitForLiveSelectorsRejectsPersistentDrift(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(selectorState{Type: "Selector", Now: "deny", All: []string{"exit-1", "deny"}})
	}))
	defer server.Close()
	client := &http.Client{Timeout: time.Second}
	config := smokeConfig{Groups: []routing.Group{{ID: "other", Exits: []string{"exit-1"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := waitForLiveSelectors(ctx, client, server.URL, config, map[string]bool{"exit-1": true}, nil); err == nil {
		t.Fatal("persistent selector drift passed smoke confirmation")
	}
}
