package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const sample = `{"groups":[{"id":"fi","exits":["fi2","fi1"]},{"id":"ru"}],"healthy":{"fi2":true},"lists":[{"id":"general","group":"fi","masks":["*.com"]},{"id":"saved","masks":["*.org"]}]}`

// TestPanelSnapshot checks order, binding, empty groups, recovery and read-only semantics through HTTP.
func TestPanelSnapshot(t *testing.T) {
	snapshot := filepath.Join(t.TempDir(), "config.json")
	h := panelHandler(snapshot, "", map[string][]byte{"index.html": []byte("panel")}, panelWrites{})
	get := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}
	for _, data := range []string{"", `{"groups":[],"healthy":{}}`, sample} {
		if data != "" {
			if err := os.WriteFile(snapshot, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
		}
		w := get("GET", "/api/groups-and-rules")
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("snapshot response allows caching")
		}
		if data != sample {
			var problem struct {
				Status int
				Detail string
			}
			if err := json.NewDecoder(w.Body).Decode(&problem); err != nil || problem.Status != 503 || problem.Detail == "" || w.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("invalid problem response: %+v, %v", problem, err)
			}
			if w.Code != 503 {
				t.Fatalf("invalid snapshot: status %d", w.Code)
			}
			continue
		}
		const want = `{"groups":[{"id":"fi","isDefault":true,"exits":[{"id":"fi2","available":true},{"id":"fi1","available":false}]},{"id":"ru","isDefault":false,"exits":[]}],"lists":[{"id":"general","group":"fi","enabled":true,"masks":["*.com"]},{"id":"saved","group":"","enabled":false,"masks":["*.org"]}]}`
		if w.Code != 200 || !bytes.Equal(bytes.TrimSpace(w.Body.Bytes()), []byte(want)) {
			t.Fatalf("status %d, got %s", w.Code, w.Body.Bytes())
		}
	}
	if w := get("POST", "/api/groups-and-rules"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", w.Code)
	}
	data, err := os.ReadFile(snapshot)
	if err != nil || string(data) != sample {
		t.Fatal("snapshot changed", err)
	}
	if w := get("GET", "/"); w.Code != 200 || w.Body.String() != "panel" {
		t.Fatalf("GET /: %d %q", w.Code, w.Body.String())
	}
}

// TestPanelAssets checks the served bundle excludes directory listings, source files and symlink targets.
func TestPanelAssets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("panel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private.json"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "private.json"), filepath.Join(dir, "leak.js")); err != nil {
		t.Fatal(err)
	}
	assets, err := readAssets(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/leak.js", "/private.json", "/.git/config", "/dir/", "/api/unknown"} {
		w := httptest.NewRecorder()
		panelHandler("", "", assets, panelWrites{}).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Errorf("%s status %d", path, w.Code)
		}
	}
}

// TestPanelLocalScope checks the HTTP Host boundary for both IP families and refuses wildcard listeners.
func TestPanelLocalScope(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8080", "[::]:8080", "1.1.1.1:8080"} {
		if _, err := localHandler(listen, http.NotFoundHandler()); err == nil {
			t.Errorf("accepted %s", listen)
		}
	}
	for _, tt := range []struct {
		listen, host string
		status       int
	}{
		{"127.0.0.1:8080", "localhost:8080", 204},
		{"192.168.42.1:8080", "192.168.42.1:8080", 204},
		{"[fd00::1]:8080", "[fd00::1]:8080", 204},
		{"192.168.42.1:8080", "foreign.example:8080", 403},
		{"192.168.42.1:8080", "localhost", 403},
	} {
		h, err := localHandler(tt.listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = tt.host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tt.status {
			t.Errorf("Host %s on %s: %d", tt.host, tt.listen, w.Code)
		}
	}
}

// TestPanelNavigation checks the navigation response independently of the controller file.
func TestPanelNavigation(t *testing.T) {
	for _, grafana := range []string{"", "https://grafana.home.arpa:8443/grafana/"} {
		h := panelHandler("", grafana, nil, panelWrites{})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/api/navigation", nil))
		if w.Code != 200 || string(bytes.TrimSpace(w.Body.Bytes())) != `{"grafanaUrl":"`+grafana+`"}` {
			t.Fatalf("navigation: %d %s", w.Code, w.Body.String())
		}
	}
}

// TestGrafanaURL checks the startup validation for links supplied by the gateway operator.
func TestGrafanaURL(t *testing.T) {
	for _, value := range []string{"", "https://grafana.home.arpa", "https://[fd00::1]:3000/grafana/?orgId=1#overview"} {
		if err := validateGrafanaURL(value); err != nil {
			t.Errorf("rejected %q: %v", value, err)
		}
	}
	for _, value := range []string{"https://grafana.home.arpa/a\u00a0b", "https://grafana.home.arpa/a\ufeffb", "javascript:alert(1)", "//grafana.home.arpa", "http://grafana.home.arpa", "https:///path", "https://user:secret@grafana.home.arpa", "https://grafana.home.arpa:65536", "https://grafana.home.arpa\\@other"} {
		if err := validateGrafanaURL(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

// TestScreenRoutes checks direct page loads while keeping missing assets, resources and nested paths distinct.
func TestScreenRoutes(t *testing.T) {
	h := panelHandler("", "", map[string][]byte{"index.html": []byte("panel")}, panelWrites{})
	for _, path := range []string{"/", "/connections", "/groups-and-rules", "/connections/missing", "/groups-and-rules.js", "/api/missing", "/unknown"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		switch path {
		case "/", "/connections", "/groups-and-rules":
			if w.Code != 200 || w.Body.String() != "panel" {
				t.Errorf("%s: %d %q", path, w.Code, w.Body.String())
			}
		default:
			if w.Code != 404 {
				t.Errorf("%s: %d", path, w.Code)
			}
		}
	}
}

// TestManagedAlias verifies read-only panels recognize alternate names for an installed snapshot.
func TestManagedAlias(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "snapshot.json")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if !sameSnapshotPath(dir+"/./snapshot.json", target) || !sameSnapshotPath(alias, target) || sameSnapshotPath(dir+"/other", target) {
		t.Fatal("incorrect managed snapshot identity")
	}
}
