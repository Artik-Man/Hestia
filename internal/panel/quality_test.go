package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/quality"
)

// TestQualityPanel exercises the real HTTP contract across startup, worker publication, stale data and edits.
func TestQualityPanel(t *testing.T) {
	dir := t.TempDir()
	files := qualityFiles{settings: filepath.Join(dir, "settings.json"), report: filepath.Join(dir, "report.json")}
	snapshot := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(snapshot, []byte(sample), 0600); err != nil {
		t.Fatal(err)
	}
	handler := panelHandler(snapshot, "", nil, panelWrites{quality: files})
	read := func() panelmodel.QualityReport {
		t.Helper()
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/quality", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("get quality: %d %s", response.Code, response.Body.String())
		}
		var view panelmodel.QualityReport
		if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
			t.Fatal(err)
		}
		return view
	}
	view := read()
	if view.CapturedAt != "" || len(view.Groups) != 2 || len(view.Groups[0].Connections) != 2 || view.Groups[1].Connections == nil || view.Groups[0].Connections[0].Result.Overall != nil {
		t.Fatalf("invalid startup report: %+v", view)
	}
	publish := func(captured time.Time) {
		t.Helper()
		view.CapturedAt = captured.UTC().Format(time.RFC3339Nano)
		data, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(files.report, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	view.Groups[0].Connections[0], view.Groups[0].Connections[1] = view.Groups[0].Connections[1], view.Groups[0].Connections[0]
	view.Groups[0].Connections[0].Active = true
	publish(time.Now())
	if current := read(); current.CapturedAt != view.CapturedAt || !current.Groups[0].Connections[0].Active || current.Groups[0].Connections[0].ID != "fi1" {
		t.Fatal("worker's order or confirmed active exit lost")
	}
	publish(time.Now().Add(-2 * time.Minute))
	if current := read(); current.CapturedAt != "" || current.Groups[0].Connections[0].Active {
		t.Fatal("stale report presented as current")
	}
	publish(time.Now())
	put := func(settings quality.Settings) int {
		t.Helper()
		data, err := json.Marshal(settings)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPut, "/api/quality/settings", bytes.NewReader(data))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	update := view.Settings
	update.WindowMinutes++
	if status := put(update); status != http.StatusOK {
		t.Fatalf("update quality settings: HTTP %d", status)
	}
	if current := read(); current.Settings.WindowMinutes != update.WindowMinutes || current.CapturedAt != "" {
		t.Fatal("old report shown for new settings")
	}
	update.WindowMinutes = 0
	if status := put(update); status != http.StatusUnprocessableEntity || read().Settings.WindowMinutes != view.Settings.WindowMinutes+1 {
		t.Fatalf("invalid request changed settings: HTTP %d", status)
	}
}

// TestIndependentQualityEdits ensures concurrent editors of different checks preserve both changes and the common window.
func TestIndependentQualityEdits(t *testing.T) {
	dir := t.TempDir()
	files := qualityFiles{settings: filepath.Join(dir, "settings.json")}
	handler := panelHandler(filepath.Join(dir, "snapshot.json"), "", nil, panelWrites{quality: files})
	send := func(method, path string, body []byte) int {
		request := httptest.NewRequest(method, path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	checks := quality.DefaultSettings().Checks
	responses := make(chan int, len(checks)+1)
	for _, check := range checks {
		check.IntervalSeconds = 47
		body, err := json.Marshal(check)
		if err != nil {
			t.Fatal(err)
		}
		go func() { responses <- send(http.MethodPut, "/api/quality/checks/"+check.Protocol, body) }()
	}
	go func() { responses <- send(http.MethodPut, "/api/quality/window", []byte(`{"windowMinutes":25}`)) }()
	for range len(checks) + 1 {
		if status := <-responses; status != http.StatusOK {
			t.Fatalf("scoped PUT: HTTP %d", status)
		}
	}
	s, err := quality.LoadSettings(files.settings)
	if err != nil || s.WindowMinutes != 25 || len(s.Checks) != len(checks) {
		t.Fatalf("unexpected settings: %+v %v", s, err)
	}
	for _, c := range s.Checks {
		if c.IntervalSeconds != 47 {
			t.Fatalf("lost edit for %s", c.Protocol)
		}
	}
	body, _ := json.Marshal(checks[0])
	if status := send(http.MethodPut, "/api/quality/checks/TCP", body); status != 422 {
		t.Fatalf("protocol mismatch: HTTP %d", status)
	}
	if status := send(http.MethodDelete, "/api/quality/checks/UDP", nil); status != http.StatusOK {
		t.Fatalf("delete: HTTP %d", status)
	}
	s, err = quality.LoadSettings(files.settings)
	if err != nil || len(s.Checks) != len(checks)-1 || s.WindowMinutes != 25 {
		t.Fatalf("delete changed unrelated settings: %+v %v", s, err)
	}
}
