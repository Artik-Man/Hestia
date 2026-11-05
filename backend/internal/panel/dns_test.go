package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
)

// dnsRequest exercises the live DNS routes with JSON and returns the actual HTTP response.
func dnsRequest(t *testing.T, handler http.Handler, method, path string, body any, origin string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}

// TestDNSPolicyHTTP verifies confirmation after storage, conflicts, failed validation, cross-origin rejection and recovery on restart.
func TestDNSPolicyHTTP(t *testing.T) {
	writes := panelWrites{dnsPolicyPath: filepath.Join(t.TempDir(), "policy.json")}
	h := panelHandler("", "", nil, writes)
	read := func(handler http.Handler) DNSPolicySnapshot {
		t.Helper()
		r := dnsRequest(t, handler, "GET", "/api/dns/policy", nil, "")
		var s DNSPolicySnapshot
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &s) != nil {
			t.Fatalf("read %d: %s", r.Code, r.Body.String())
		}
		return s
	}
	initial := read(h)
	change := DNSPolicyUpdate{ExpectedRevision: initial.Revision, Policy: initial.Policy}
	change.Policy.Manual = []string{"Warm.Example."}
	change.Policy.Exclusions = []string{"warm.example"}
	put := func(handler http.Handler, want int, origin string) {
		t.Helper()
		result := dnsRequest(t, handler, "PUT", "/api/dns/policy", change, origin)
		if result.Code != want {
			t.Fatalf("wanted %d, got %d: %s", want, result.Code, result.Body.String())
		}
	}
	put(h, 403, "https://foreign.example")
	put(panelHandler("", "", nil, panelWrites{}), 503, "")
	put(h, 200, "")
	put(h, 409, "")
	saved := read(panelHandler("", "", nil, writes))
	if !slices.Equal(saved.Policy.Manual, []string{"warm.example"}) || !slices.Equal(saved.Policy.Exclusions, saved.Policy.Manual) || saved.Revision == change.ExpectedRevision {
		t.Fatalf("unexpected policy after restart: %+v", saved)
	}
	change.ExpectedRevision = saved.Revision
	change.Policy.Exclusions = []string{"*.example"}
	put(h, 422, "")
	if current := read(h); current.Revision != saved.Revision || !slices.Equal(current.Policy.Exclusions, saved.Policy.Exclusions) {
		t.Fatalf("invalid write changed policy: %+v", current)
	}
}

// TestDNSWarmAvailability distinguishes unavailable measurements from an authoritative empty observation.
func TestDNSWarmAvailability(t *testing.T) {
	path := "/api/dns/warm"
	absent := dnsRequest(t, panelHandler("", "", nil, panelWrites{}), "GET", path, nil, "")
	if absent.Code != 503 {
		t.Fatalf("unavailable measurement: %d", absent.Code)
	}
	pathToReport := filepath.Join(t.TempDir(), "report.json")
	data, err := json.Marshal(dnspolicy.DNSWarmReport{ObservedAt: time.Now().UTC(), Automatic: []dnspolicy.DNSWarmName{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathToReport, data, 0600); err != nil {
		t.Fatal(err)
	}
	empty := dnsRequest(t, panelHandler("", "", nil, panelWrites{dnsReportPath: pathToReport}), "GET", path, nil, "")
	var report dnspolicy.DNSWarmReport
	if empty.Code != 200 || json.Unmarshal(empty.Body.Bytes(), &report) != nil || report.Automatic == nil || len(report.Automatic) != 0 {
		t.Fatalf("empty measurement: %d %s", empty.Code, empty.Body.String())
	}
}
