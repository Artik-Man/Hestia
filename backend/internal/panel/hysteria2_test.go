package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/google/uuid"
)

// TestHysteria2API verifies create assigns a UUID and malformed or private input stays out of error responses.
func TestHysteria2API(t *testing.T) {
	const secret = "secret-marker"
	const body = `{"name":"Офис","server":"vpn.example","port":443,"group":"main","underlay":"uplink","password":"secret-marker"}`
	const id = "2c3918e0-727f-4feb-bbab-3ebd956e3d22"
	for _, tc := range []struct {
		method, path, body, mode string
		status                   int
	}{
		{"POST", hysteriaPath, body, "-hysteria2-create", 200},
		{"PUT", hysteriaPath + "/" + id, `{"name":"Офис","server":"vpn.example","port":443,"underlay":"uplink"}`, "-hysteria2-update", 200},
		{"POST", hysteriaPath, strings.Replace(body, secret, "", 1), "", 422},
		{"POST", hysteriaPath, strings.Replace(body, "443", "65536", 1), "", 422},
		{"POST", hysteriaPath, strings.Replace(body, "vpn.example", "vpn.example:443-444", 1), "", 422},
		{"POST", hysteriaPath, body[:len(body)-1], "", 400},
		{"POST", hysteriaPath, strings.Replace(body, `"port":443`, `"port":"secret-marker"`, 1), "", 422},
		{"POST", hysteriaPath, strings.Replace(body, `"password":"secret-marker"`, `"password":{"secret-marker":1}`, 1), "", 422},
		{"DELETE", hysteriaPath + "/" + id, "", "-hysteria2-delete", 204},
		{"GET", hysteriaPath, "", "-hysteria2-list", 200},
		{"GET", hysteriaPath + "/" + id, "", "-hysteria2-read", 200},
	} {
		mode := ""
		h := panelHandler("", "", nil, panelWrites{physical: func(_ context.Context, op string, in, out any) error {
			mode = op
			if op == "-hysteria2-read" {
				if in.(panelmodel.AWGIDRequest).ID != id {
					t.Fatal("wrong credential request")
				}
				*out.(*panelmodel.Hysteria2ConnectionProfile) = panelmodel.Hysteria2ConnectionProfile{Hysteria2Connection: panelmodel.Hysteria2Connection{ID: id}, Password: secret}
			}
			if op == "-hysteria2-create" || op == "-hysteria2-update" {
				req := in.(panelmodel.Hysteria2Command)
				parsed, err := uuid.Parse(req.ID)
				if err != nil || parsed.Version() != 4 || (op == "-hysteria2-create" && req.Password != secret) || (op == "-hysteria2-update" && (req.ID != id || req.Password != "")) {
					t.Fatal("invalid save command")
				}
				*out.(*panelmodel.Hysteria2Connection) = panelmodel.Hysteria2Connection{Hysteria2Settings: req.Hysteria2Settings, ID: req.ID, Group: "main", Priority: 1}
			}
			return nil
		}})
		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if res.Code != tc.status || mode != tc.mode || strings.Contains(res.Body.String(), secret) != (tc.mode == "-hysteria2-read") || res.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: status %d mode %q", tc.method, tc.path, res.Code, mode)
		}
	}
}

// TestHysteria2Availability verifies both panel views receive only fresh evidence for this generation and matching exit IDs.
func TestHysteria2Availability(t *testing.T) {
	dir := t.TempDir()
	snapshot := filepath.Join(dir, "snapshot.json")
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(snapshot, []byte(`{"groups":[{"id":"main","exits":["eth","tunnel"]}],"lists":[],"healthy":{"eth":true,"tunnel":true},"connectorKinds":{"tunnel":"hysteria2"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler := panelHandler(snapshot, "", nil, panelWrites{quality: qualityFiles{report: path}})
	verify := func(expected bool) {
		t.Helper()
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, httptest.NewRequest("GET", "/api/groups-and-rules", nil))
		var view panelmodel.Snapshot
		if err := json.Unmarshal(writer.Body.Bytes(), &view); err != nil || writer.Code != 200 || len(view.Groups) != 1 || len(view.Groups[0].Exits) != 2 {
			t.Fatalf("bad snapshot %d", writer.Code)
		}
		exits := view.Groups[0].Exits
		if !exits[0].Available || exits[1].Available != expected {
			t.Fatalf("unexpected exit availability: %v", exits)
		}
	}
	verify(false)
	for _, tc := range []struct {
		group        string
		age          time.Duration
		up, expected bool
	}{
		{"main", 0, true, true}, {"main", 0, false, false}, {"old", 0, true, false}, {"main", 2 * time.Minute, true, false}, {"main", 20 * time.Second, true, false},
	} {
		report := panelmodel.QualityReport{CapturedAt: time.Now().Add(-tc.age).UTC().Format(time.RFC3339Nano), Groups: []panelmodel.QualityGroup{{ID: tc.group, Connections: []panelmodel.QualityConnection{{ID: "tunnel", Available: tc.up}, {ID: "eth"}}}}}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		verify(tc.expected)
	}
}
