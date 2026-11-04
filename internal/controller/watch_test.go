package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestWatcherUsesAWGHeartbeatForFailover sends an unavailable AWG selector to its backup and restores it only after a fresh heartbeat.
func TestWatcherUsesAWGHeartbeatForFailover(t *testing.T) {
	transport := &selectorTransport{selected: "awg-test"}
	watcher := newWatcher(&http.Client{Transport: transport}, "http://sing-box.test")
	healthy := false
	watcher.healthyAWG = func(id string) bool { return id == "awg-test" && healthy }
	snapshot := []byte(`{"groups":[{"id":"default","exits":["awg-test","direct-test"]}],"lists":[],"healthy":{"awg-test":true,"direct-test":true},"connectorKinds":{"awg-test":"awg"}}`)
	if _, err := watcher.step(context.Background(), snapshot); err != nil || transport.selected != "direct-test" {
		t.Fatalf("missing heartbeat did not fail over: selected=%q err=%v", transport.selected, err)
	}
	healthy = true
	if _, err := watcher.step(context.Background(), snapshot); err != nil || transport.selected != "awg-test" {
		t.Fatalf("fresh heartbeat did not restore AWG: selected=%q err=%v", transport.selected, err)
	}
}

type selectorTransport struct {
	selected string
}

// RoundTrip simulates the local selector API in memory so the failover test needs no socket permissions.
func (transport *selectorTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	status, payload := http.StatusNoContent, []byte(nil)
	if request.Method == http.MethodGet {
		status = http.StatusOK
		payload, _ = json.Marshal(selector{Type: "Selector", Now: transport.selected, All: []string{"awg-test", "direct-test", "deny"}})
	} else {
		var body struct{ Name string }
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			return nil, err
		}
		transport.selected = body.Name
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload)), Request: request}, nil
}

// TestAWGHealthRecordFreshness rejects wrong connector IDs, stale times and future-dated heartbeats.
func TestAWGHealthRecordFreshness(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	base := awgHealthRecord{ID: "awg-test", UpdatedAt: now.Add(-time.Second), Status: "ready"}
	if !validAWGHealthRecord(base, "awg-test", now) {
		t.Fatal("fresh valid record rejected")
	}
	for _, record := range []awgHealthRecord{
		{ID: "other", UpdatedAt: now, Status: "ready"},
		{ID: "awg-test", UpdatedAt: now.Add(-awgHealthMaxAge - time.Second), Status: "ready"},
		{ID: "awg-test", UpdatedAt: now.Add(2 * time.Second), Status: "ready"},
		{ID: "awg-test", UpdatedAt: now, Status: "failed"},
	} {
		if validAWGHealthRecord(record, "awg-test", now) {
			t.Fatalf("invalid record accepted: %+v", record)
		}
	}
}
