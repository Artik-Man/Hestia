package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/geoip"
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
	traceEvent := traffic.TrafficEvent{Time: time.Now().UTC().Add(-3 * time.Hour), Address: "2001:db8::5", Protocol: "UDP", Port: 443, Kind: traffic.Unconfirmed, Connection: "old-fi", Trace: &traffic.TraceEvidence{SessionID: "20261109T120000.000000000Z", StartedAt: time.Now().UTC(), DurationMs: 15000, PolicyKey: "Policy2", ConfiguredMark: 0x0ffffaac, NDMTable: 4102, HestiaTable: 32732, Source: "192.0.2.4", SourcePort: 49322, Destination: "192.0.2.5", DestinationPort: 443, Stages: []traffic.TraceStage{{Name: "br0", Status: "observed", Count: 2, ReverseCount: 1}, {Name: "policy_mark", Status: "unavailable"}}}}
	if err = store.Append(t.Context(), traceEvent); err != nil {
		t.Fatal(err)
	}
	unknownEvent := traffic.TrafficEvent{Time: time.Now().UTC(), Address: "203.0.113.4", Protocol: "TCP", Port: 443, Kind: traffic.Unconfirmed}
	if err = store.Append(t.Context(), unknownEvent); err != nil {
		t.Fatal(err)
	}
	h := panelHandler("", "", nil, panelWrites{traffic: store})
	res := dnsRequest(t, h, http.MethodGet, "/api/traffic?query=db8&protocol=UDP&output=connection%3Aold-fi&limit=1", nil, "")
	var page traffic.TrafficPage
	if err = json.Unmarshal(res.Body.Bytes(), &page); err != nil || res.Code != 200 || page.Total != 1 || len(page.Events) != 1 || page.Events[0].Port != 443 || page.SourceAvailable || page.Events[0].Trace == nil || page.Events[0].Trace.SourcePort != 49322 || len(page.Events[0].Trace.Stages) != 2 || page.Events[0].Trace.Stages[0].ReverseCount != 1 {
		t.Fatalf("status %d: %s err=%v", res.Code, res.Body.String(), err)
	}
	res = dnsRequest(t, h, http.MethodGet, "/api/traffic?output=unknown&limit=1", nil, "")
	if err = json.Unmarshal(res.Body.Bytes(), &page); err != nil || res.Code != 200 || page.Total != 1 || len(page.Events) != 1 || page.Events[0].Address != "203.0.113.4" {
		t.Fatalf("unknown output: %d %s err=%v", res.Code, res.Body.String(), err)
	}
	for _, query := range []string{"?limit=501", "?from=invalid", "?protocol=ICMP", "?output=invalid", "?snapshot=future"} {
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
	if err = json.Unmarshal(res.Body.Bytes(), &page); err != nil || page.Total != 2 {
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

// TestGeoIPJournalAPI checks current country labels, filtering before pagination and disclosure of the saved token only on successful settings requests.
func TestGeoIPJournalAPI(t *testing.T) {
	dir := t.TempDir()
	store, err := traffic.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dbBytes := append([]byte{'H', 'G', 'I', '1', 0, 0, 0, 2}, 9, 9, 9, 0, 9, 9, 9, 255, 'C', 'H', 11, 0, 0, 0, 11, 0, 0, 255, 'S', 'E')
	file := filepath.Join(dir, "geo.bin")
	if err = os.WriteFile(file, dbBytes, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := geoip.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := geoip.NewEnrichment(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	h := panelHandler("", "", nil, panelWrites{traffic: store, trafficCountries: db, enrichment: provider})
	for _, e := range []traffic.TrafficEvent{{Address: "9.9.9.9"}, {Address: "11.0.0.1"}, {Address: "", Domain: "vk.ru", FakeIP: "9.9.9.9"}} {
		e.Time = time.Now()
		e.Protocol = "TCP"
		e.Kind = traffic.Unconfirmed
		if err = store.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	res := dnsRequest(t, h, http.MethodGet, "/api/traffic", nil, "")
	var page traffic.TrafficPage
	if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &page) != nil || len(page.Events) != 3 || page.Events[0].Country != "" || page.Events[1].CountryName != "Швеция" || page.Events[2].CountryName != "Швейцария" {
		t.Fatalf("journal: %s", res.Body.String())
	}
	for _, tc := range []struct {
		term   string
		offset string
		total  int
		code   string
	}{
		{"  шВ  ", "0", 2, "SE"},
		{"шв", "1", 2, "CH"},
		{"опреДел", "0", 1, ""},
	} {
		var filtered traffic.TrafficPage
		res = dnsRequest(t, h, http.MethodGet, "/api/traffic?limit=1&offset="+tc.offset+"&country="+url.QueryEscape(tc.term), nil, "")
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &filtered) != nil || filtered.Total != tc.total || len(filtered.Events) != 1 || filtered.Events[0].Country != tc.code {
			t.Fatalf("country query %q, offset %s: %s", tc.term, tc.offset, res.Body.String())
		}
	}
	const secret = "private-test-token"
	for _, req := range []struct {
		method string
		body   any
		want   int
		token  string
	}{
		{http.MethodGet, nil, 200, ""},
		{http.MethodPut, map[string]string{"token": secret}, 200, secret},
		{http.MethodGet, nil, 200, secret},
		{http.MethodPut, map[string]string{"wrong": secret}, 422, ""},
		{http.MethodPut, map[string]string{"token": strings.Repeat(secret, 20)}, 422, ""},
		{http.MethodPut, map[string]string{"token": secret + " x"}, 422, ""},
		{http.MethodGet, nil, 200, secret},
		{http.MethodPut, map[string]string{"token": ""}, 200, ""},
		{http.MethodGet, nil, 200, ""},
	} {
		res = dnsRequest(t, h, req.method, geoIPSettingsPath, req.body, "")
		if res.Code != req.want || res.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("unexpected settings response: status %d, expected %d", res.Code, req.want)
		}
		if req.want != http.StatusOK {
			if strings.Contains(res.Body.String(), secret) {
				t.Fatal("settings error disclosed the token")
			}
			continue
		}
		var state struct {
			Token      *string
			Configured *bool
		}
		if json.Unmarshal(res.Body.Bytes(), &state) != nil || state.Token == nil || *state.Token != req.token || state.Configured == nil || *state.Configured != (req.token != "") {
			t.Fatal("settings response did not report the stored token and its configured state")
		}
	}
	req := httptest.NewRequest(http.MethodPut, geoIPSettingsPath, strings.NewReader(`{"token":"`+secret))
	req.Header.Set("Content-Type", "application/json")
	malformed := httptest.NewRecorder()
	h.ServeHTTP(malformed, req)
	if malformed.Code < 400 || strings.Contains(malformed.Body.String(), secret) {
		t.Fatalf("malformed JSON leaked or accepted: %d", malformed.Code)
	}
}

// TestTrafficQUICHTTP accepts the generated protocol filter and returns only confirmed QUIC events.
func TestTrafficQUICHTTP(t *testing.T) {
	store, err := traffic.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, protocol := range []string{"UDP", "QUIC"} {
		if err := store.Append(t.Context(), traffic.TrafficEvent{Time: time.Now().UTC(), Address: "192.0.2.2", Protocol: protocol, Port: 443, Kind: traffic.Unconfirmed}); err != nil {
			t.Fatal(err)
		}
	}
	h := panelHandler("", "", nil, panelWrites{traffic: store})
	res := dnsRequest(t, h, http.MethodGet, "/api/traffic?protocol=QUIC&limit=10", nil, "")
	var page traffic.TrafficPage
	if err := json.Unmarshal(res.Body.Bytes(), &page); err != nil || res.Code != 200 || page.Total != 1 || len(page.Events) != 1 || page.Events[0].Protocol != "QUIC" {
		t.Fatalf("QUIC page: %d %s err=%v", res.Code, res.Body.String(), err)
	}
}
