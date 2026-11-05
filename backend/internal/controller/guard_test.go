package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestGuardBarrier verifies write ordering across successful reconfiguration and interrupted transitions.
func TestGuardBarrier(t *testing.T) {
	for _, tc := range []struct {
		name        string
		healthy     map[string]bool
		failTag     string
		loseOpenAck bool
		writes      []string
		target      string
		wantErr     bool
	}{
		{"outage", map[string]bool{}, "", false, []string{"fi-gate:deny"}, "deny", false},
		{"primary_only", map[string]bool{"fi1": true}, "", false, []string{"fi-gate:deny", "fi:fi1", "fi-alt:fi1", "fi-gate:fi-dispatch"}, "fi-dispatch", false},
		{"inner_failure", map[string]bool{"fi1": true}, "fi-alt", false, []string{"fi-gate:deny", "fi:fi1", "fi-alt:fi1"}, "deny", true},
		{"uncertain_open", map[string]bool{"fi1": true}, "", true, []string{"fi-gate:deny", "fi:fi1", "fi-alt:fi1", "fi-gate:fi-dispatch", "fi-gate:deny"}, "deny", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := map[string]string{"fi": "fi2", "fi-alt": "fi2", "fi-gate": "fi-dispatch"}
			var writes []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tag := strings.TrimPrefix(r.URL.Path, "/proxies/")
				if _, ok := state[tag]; !ok {
					t.Errorf("unexpected selector %q", tag)
					w.WriteHeader(404)
					return
				}
				if r.Method == "GET" {
					members := []string{"fi1", "fi2", "deny"}
					if tag == "fi-gate" {
						members = []string{"fi-dispatch", "deny"}
					}
					json.NewEncoder(w).Encode(selector{Type: "Selector", Now: state[tag], All: members})
					return
				}
				var req struct{ Name string }
				json.NewDecoder(r.Body).Decode(&req)
				writes = append(writes, tag+":"+req.Name)
				if tc.failTag == tag {
					w.WriteHeader(503)
					return
				}
				state[tag] = req.Name
				if tc.loseOpenAck && tag == "fi-gate" && req.Name == "fi-dispatch" {
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			cfg, err := CheckSnapshot([]byte(healthy))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Healthy = tc.healthy
			rep, err := guard(context.Background(), server.Client(), server.URL, cfg, "fi")
			if (err != nil) != tc.wantErr || state["fi-gate"] != tc.target || rep.Gate != tc.target || !slices.Equal(writes, tc.writes) {
				t.Fatalf("report=%+v state=%v writes=%v err=%v", rep, state, writes, err)
			}
			if tc.name == "primary_only" {
				writes = nil
				again, err := guard(context.Background(), server.Client(), server.URL, cfg, "fi")
				if err != nil || again.Gate != "fi-dispatch" || !slices.Equal(writes, []string{"fi-gate:deny", "fi-gate:fi-dispatch"}) {
					t.Fatalf("repeated transition must close and reopen; report=%+v writes=%v err=%v", again, writes, err)
				}
			}
		})
	}
}
