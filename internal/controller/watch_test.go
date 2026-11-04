package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWatcherReconcilesOnlyDivergentSelectors checks that retries repair FI
// without rewriting RU and that a later poll repairs an externally reset target.
func TestWatcherReconcilesOnlyDivergentSelectors(t *testing.T) {
	selected := map[string]string{"ru": "deny", "fi": "deny"}
	members := map[string][]string{"ru": {"ru1", "deny"}, "fi": {"fi1", "fi2", "deny"}}
	writes := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		group := strings.TrimPrefix(r.URL.Path, "/proxies/")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(selector{Type: "Selector", Now: selected[group], All: members[group]})
			return
		}
		writes[group]++
		if group == "fi" && writes[group] == 1 {
			http.Error(w, "retry", 503)
			return
		}
		var body struct{ Name string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		selected[group] = body.Name
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	snapshot := []byte(healthy)
	watcher := newWatcher(server.Client(), server.URL)
	step := func(wantErr bool) {
		t.Helper()
		_, err := watcher.step(context.Background(), snapshot)
		if (err != nil) != wantErr {
			t.Fatalf("error=%v", err)
		}
	}
	step(true)
	step(false)
	step(false)
	if writes["ru"] != 1 || writes["fi"] != 2 {
		t.Fatal(writes)
	}
	snapshot = []byte(strings.Replace(healthy, "*.example.org", "broken", 1))
	step(true)
	if selected["fi"] != "fi2" {
		t.Fatal(selected)
	}
	snapshot = []byte(strings.Replace(healthy, `"fi2":true`, `"fi2":false`, 1))
	step(false)
	if selected["fi"] != "deny" || writes["ru"] != 1 {
		t.Fatal(selected, writes)
	}
	selected["fi"] = "fi1" // emulate sing-box restart
	step(false)
	if selected["fi"] != "deny" || writes["fi"] != 4 {
		t.Fatal(fmt.Sprint(selected, writes))
	}
}

// TestWatcherPinsTopologyOnlyAfterFirstConfirmation verifies that an initial API
// mismatch can be corrected and that later topology replacements are rejected.
func TestWatcherPinsTopologyOnlyAfterFirstConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies/ru" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(selector{Type: "Selector", Now: "ru1", All: []string{"ru1", "deny"}})
	}))
	defer server.Close()
	w := newWatcher(server.Client(), server.URL)
	snapshot := func(group string) []byte {
		return []byte(fmt.Sprintf(`{"groups":[{"id":%q,"exits":["ru1"]}],"healthy":{"ru1":true}}`, group))
	}
	if _, err := w.step(context.Background(), snapshot("wrong")); err == nil {
		t.Fatal("absent selector accepted")
	}
	results, err := w.step(context.Background(), snapshot("ru"))
	if err != nil || len(results) != 1 || results[0].Reason != "availability_snapshot" {
		t.Fatalf("results=%v err=%v", results, err)
	}
	if _, err = w.step(context.Background(), snapshot("wrong")); err == nil || w.desired.Groups[0].ID != "ru" {
		t.Fatal("accepted topology replacement")
	}
}
