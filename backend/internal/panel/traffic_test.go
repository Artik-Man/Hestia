package panel

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
)

// TestTrafficHTTP exercises the registered API including combined filters, validation and settings durability.
func TestTrafficHTTP(t *testing.T) {
	dir := t.TempDir()
	store, err := traffic.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Append(t.Context(), traffic.TrafficEvent{Time: time.Now().UTC().Add(-3 * time.Hour), Address: "2001:db8::5", Protocol: "UDP", Port: 443, Kind: traffic.Unconfirmed, Connection: "old-fi"}); err != nil {
		t.Fatal(err)
	}
	h := panelHandler("", "", nil, panelWrites{traffic: store})
	res := dnsRequest(t, h, http.MethodGet, "/api/traffic?query=db8&protocol=UDP&output=connection%3Aold-fi&limit=1", nil, "")
	var page traffic.TrafficPage
	if err = json.Unmarshal(res.Body.Bytes(), &page); err != nil || res.Code != 200 || page.Total != 1 || len(page.Events) != 1 || page.Events[0].Port != 443 || page.SourceAvailable {
		t.Fatalf("status %d: %s err=%v", res.Code, res.Body.String(), err)
	}
	for _, query := range []string{"?limit=501", "?from=invalid", "?protocol=ICMP", "?output=unknown", "?snapshot=future"} {
		if res = dnsRequest(t, h, http.MethodGet, "/api/traffic"+query, nil, ""); res.Code != 422 {
			t.Errorf("query %s: %d", query, res.Code)
		}
	}
	const settings = "/api/traffic/settings"
	res = dnsRequest(t, h, http.MethodGet, settings, nil, "")
	var expected traffic.TrafficSettings
	if err = json.Unmarshal(res.Body.Bytes(), &expected); err != nil || res.Code != 200 || expected.MaxMB != 1024 || expected.RetentionHours != 24 {
		t.Fatalf("read settings: %s err=%v", res.Body.String(), err)
	}
	body := map[string]traffic.TrafficSettings{"expected": expected, "proposed": {MaxMB: 64, RetentionHours: 72}}
	if res = dnsRequest(t, h, http.MethodPut, settings, body, "https://foreign.invalid"); res.Code != 403 {
		t.Fatalf("cross-origin update: %d", res.Code)
	}
	if res = dnsRequest(t, h, http.MethodPut, settings, body, ""); res.Code != 200 {
		t.Fatalf("settings: %d %s", res.Code, res.Body.String())
	}
	body["proposed"] = traffic.TrafficSettings{MaxMB: 1, RetentionHours: 1}
	if res = dnsRequest(t, h, http.MethodPut, settings, body, ""); res.Code != 409 {
		t.Fatalf("stale update: %d %s", res.Code, res.Body.String())
	}
	res = dnsRequest(t, h, http.MethodGet, "/api/traffic", nil, "")
	if err = json.Unmarshal(res.Body.Bytes(), &page); err != nil || page.Total != 1 {
		t.Fatalf("stale update pruned history: %s err=%v", res.Body.String(), err)
	}
	if res = dnsRequest(t, h, http.MethodPut, settings, map[string]int{"maxMB": 0, "retentionHours": 1}, ""); res.Code != 422 {
		t.Fatalf("invalid settings: %d", res.Code)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := traffic.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	res = dnsRequest(t, panelHandler("", "", nil, panelWrites{traffic: reopened}), http.MethodGet, settings, nil, "")
	var cfg traffic.TrafficSettings
	if err = json.Unmarshal(res.Body.Bytes(), &cfg); err != nil || res.Code != 200 || cfg.MaxMB != 64 || cfg.RetentionHours != 72 {
		t.Fatalf("reopened settings: %s err=%v", res.Body.String(), err)
	}
	offline := panelHandler("", "", nil, panelWrites{})
	if res = dnsRequest(t, offline, http.MethodGet, "/api/traffic", nil, ""); res.Code != 503 {
		t.Fatalf("missing store: %d", res.Code)
	}
}
