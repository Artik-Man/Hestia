package panel

import (
	"context"
	"encoding/json"
	"github.com/Artik-Man/Hestia/internal/binding"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// TestConnectionEnabledHTTP bounds state changes, requires explicit booleans and verifies committed acknowledgements.
func TestConnectionEnabledHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, path, body          string
		writer, mismatch, failure bool
		want                      int
	}{
		{"disable", "vpn", `{"enabled":false}`, true, false, false, 200},
		{"enable", "vpn", `{"enabled":true}`, true, false, false, 200},
		{"missing", "vpn", `{}`, true, false, false, 422},
		{"null", "vpn", `{"enabled":null}`, true, false, false, 422},
		{"string", "vpn", `{"enabled":"false"}`, true, false, false, 422},
		{"unknown field", "vpn", `{"enabled":false,"script":"x"}`, true, false, false, 422},
		{"invalid id", "INVALID!", `{"enabled":false}`, true, false, false, 422},
		{"readonly", "vpn", `{"enabled":false}`, false, false, false, 503},
		{"not found", "vpn", `{"enabled":false}`, true, false, true, 404},
		{"unconfirmed", "vpn", `{"enabled":false}`, true, true, false, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			var writes panelWrites
			if tc.writer {
				writes.connectionEnabled = func(_ context.Context, id string, enabled bool) (panelmodel.ConnectionEnabled, error) {
					calls++
					if tc.failure {
						return panelmodel.ConnectionEnabled{}, huma.Error404NotFound("missing")
					}
					if tc.mismatch {
						enabled = !enabled
					}
					return panelmodel.ConnectionEnabled{ID: id, Enabled: enabled}, nil
				}
			}
			req := httptest.NewRequest(http.MethodPut, "/api/connections/"+tc.path+"/enabled", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			panelHandler("", "", nil, writes).ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status %d want %d: %s", res.Code, tc.want, res.Body)
			}
			if (calls > 0) != (tc.want == 200 || tc.failure || tc.mismatch) {
				t.Fatalf("unexpected dispatch count %d", calls)
			}
			if res.Code == 200 {
				var got panelmodel.ConnectionEnabled
				if json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ID != "vpn" || got.Enabled != strings.Contains(tc.body, "true") {
					t.Fatalf("bad confirmation %s", res.Body)
				}
			}
		})
	}
}

// TestConnectionEnabledRejectsCrossOrigin blocks browser state mutations before the privileged writer is called.
func TestConnectionEnabledRejectsCrossOrigin(t *testing.T) {
	calls := 0
	handler := panelHandler("", "", nil, panelWrites{connectionEnabled: func(_ context.Context, id string, enabled bool) (panelmodel.ConnectionEnabled, error) {
		calls++
		return panelmodel.ConnectionEnabled{ID: id, Enabled: enabled}, nil
	}})
	req := httptest.NewRequest(http.MethodPut, "http://gateway.test/api/connections/vpn/enabled", strings.NewReader(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://untrusted.test")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("status %d, calls %d", res.Code, calls)
	}
}

// connectionDeadlineRecorder observes the live response-controller deadline without opening a network socket.
type connectionDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

// SetWriteDeadline records the deadline selected by the handler for a potentially slow activation.
func (r *connectionDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	return nil
}

// TestConnectionEnabledWriteDeadline permits activation and rollback while retaining ordinary response limits elsewhere.
func TestConnectionEnabledWriteDeadline(t *testing.T) {
	handler, err := localHandler("127.0.0.1:8080", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		extended     bool
	}{
		{http.MethodPut, "/api/connections/vpn/enabled", true},
		{http.MethodPut, "/api/awg/vpn", true},
		{http.MethodPost, "/api/awg", true},
		{http.MethodGet, "/api/connections/vpn/enabled", false},
		{http.MethodPut, "/api/connections/vpn/name", false},
		{http.MethodPut, "/api/groups/vpn", false},
	} {
		res := &connectionDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		start := time.Now()
		handler.ServeHTTP(res, httptest.NewRequest(tc.method, "http://127.0.0.1:8080"+tc.path, nil))
		if tc.extended {
			want := 2*binding.AWGActivationLimit + time.Minute
			elapsed := res.deadline.Sub(start)
			if elapsed < want || elapsed > want+time.Second {
				t.Fatalf("%s %s deadline=%s", tc.method, tc.path, elapsed)
			}
		} else if !res.deadline.IsZero() {
			t.Fatalf("ordinary route %s extended", tc.path)
		}
	}
}
