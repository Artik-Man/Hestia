package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestCountryMapAPI exercises persistence, version conflicts and full-map validation through HTTP.
func TestCountryMapAPI(t *testing.T) {
	dir := t.TempDir()
	inventory := filepath.Join(dir, "snapshot.json")
	path := filepath.Join(dir, "countries.json")
	if err := os.WriteFile(inventory, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(change any, want int) panelmodel.CountryMap {
		t.Helper()
		handler := panelHandler(inventory, "", nil, panelWrites{countryMap: binding.CustomCountryMap(inventory, path)})
		method := http.MethodGet
		var payload []byte
		if change != nil {
			method = http.MethodPut
			var err error
			payload, err = json.Marshal(change)
			if err != nil {
				t.Fatal(err)
			}
		}
		req := httptest.NewRequest(method, "/api/country-map", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s: got %d, want %d: %s", method, w.Code, want, w.Body.String())
		}
		var got panelmodel.CountryMap
		if want == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
		}
		return got
	}
	first := call(nil, 200)
	if first.Enabled || len(first.Assignments) != 249 || first.Version == "" {
		t.Fatal("incomplete or enabled initial map")
	}
	for code, group := range first.Assignments {
		if group != "fi" {
			t.Fatalf("%s initialized to %s", code, group)
		}
	}
	if err := os.WriteFile(inventory, []byte(`{"groups":[{"id":"ru"},{"id":"fi"}],"healthy":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	previous := call(nil, 200)
	if previous.Version != first.Version || previous.Assignments["DE"] != "fi" {
		t.Fatal("new default reinitialized assignments")
	}
	previous.Enabled = true
	previous.Assignments["DE"] = "ru"
	applied := call(previous, 200)
	if applied.Version == previous.Version || !applied.Enabled || applied.Assignments["DE"] != "ru" {
		t.Fatal("write not confirmed")
	}
	call(first, 409)
	call(map[string]any{"assignments": applied.Assignments, "version": applied.Version}, 422)
	applied.Assignments["DE"] = "missing"
	call(applied, 422)
	delete(applied.Assignments, "DE")
	call(applied, 422)
	applied.Assignments["ZZ"] = "fi"
	call(applied, 422)
	got := call(nil, 200)
	if got.Version != applied.Version || got.Assignments["DE"] != "ru" {
		t.Fatal("invalid or stale write replaced policy")
	}
}
