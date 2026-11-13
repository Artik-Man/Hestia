package panel

import (
	"context"
	"encoding/json"
	"fmt"
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

// TestConnectionOperationReceipts confirms terminal outcomes and prevents replaying a UUID as another mutation.
func TestConnectionOperationReceipts(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed=%v", failed), func(t *testing.T) {
			calls := 0
			handler := panelHandler("", "", nil, panelWrites{connectionEnabled: func(_ context.Context, id string, enabled bool) (panelmodel.ConnectionEnabled, error) {
				calls++
				if failed {
					return panelmodel.ConnectionEnabled{}, huma.Error503ServiceUnavailable("private-helper-note")
				}
				return panelmodel.ConnectionEnabled{ID: id, Enabled: enabled}, nil
			}})
			operation := "12345678-1234-4abc-8123-456789abcdef"
			body := `{"enabled":false,"operationId":"` + operation + `"}`
			for range 2 {
				res := connectionOperationRequest(handler, http.MethodPut, "/api/connections/vpn/enabled", body)
				want := http.StatusOK
				if failed {
					want = http.StatusServiceUnavailable
				}
				if res.Code != want {
					t.Fatalf("PUT status=%d body=%s", res.Code, res.Body)
				}
			}
			if calls != 1 {
				t.Fatalf("helper dispatched %d times", calls)
			}
			res := connectionOperationRequest(handler, http.MethodGet, "/api/connections/operations/"+operation, "")
			var receipt panelmodel.ConnectionEnabledOperation
			if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &receipt) != nil {
				t.Fatalf("GET status=%d body=%s", res.Code, res.Body)
			}
			want := panelmodel.ConnectionOperationSucceeded
			if failed {
				want = panelmodel.ConnectionOperationFailed
			}
			if receipt.OperationID != operation || receipt.ID != "vpn" || receipt.Enabled || receipt.State != want || (receipt.Status == http.StatusOK) == failed {
				t.Fatalf("unexpected receipt %#v", receipt)
			}
			if strings.Contains(res.Body.String(), "private-helper-note") {
				t.Fatal("helper detail leaked into receipt")
			}
			for _, request := range []struct{ path, body string }{
				{"/api/connections/other/enabled", body},
				{"/api/connections/vpn/enabled", `{"enabled":true,"operationId":"` + operation + `"}`},
			} {
				res = connectionOperationRequest(handler, http.MethodPut, request.path, request.body)
				if res.Code != http.StatusConflict {
					t.Fatalf("mismatch=%d %s", res.Code, res.Body)
				}
			}
			if calls != 1 {
				t.Fatal("mismatched UUID dispatched helper")
			}
		})
	}
}

// TestConnectionOperationPending permits progress reads without duplicate helper execution.
func TestConnectionOperationPending(t *testing.T) {
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	handler := panelHandler("", "", nil, panelWrites{connectionEnabled: func(_ context.Context, id string, enabled bool) (panelmodel.ConnectionEnabled, error) {
		close(started)
		<-release
		return panelmodel.ConnectionEnabled{ID: id, Enabled: enabled}, nil
	}})
	operation := "12345678-1234-4abc-8123-456789abcdef"
	body := `{"enabled":false,"operationId":"` + operation + `"}`
	go func() {
		defer close(finished)
		connectionOperationRequest(handler, http.MethodPut, "/api/connections/vpn/enabled", body)
	}()
	<-started
	res := connectionOperationRequest(handler, http.MethodGet, "/api/connections/operations/"+operation, "")
	var receipt panelmodel.ConnectionEnabledOperation
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &receipt) != nil || receipt.State != panelmodel.ConnectionOperationPending || receipt.Status != 0 {
		t.Errorf("pending=%d %s", res.Code, res.Body)
	}
	res = connectionOperationRequest(handler, http.MethodPut, "/api/connections/vpn/enabled", body)
	if res.Code != http.StatusConflict {
		t.Errorf("duplicate pending=%d %s", res.Code, res.Body)
	}
	close(release)
	<-finished
}

// connectionOperationRequest invokes the public handler without a socket or privileged helper.
func connectionOperationRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}

// TestConnectionOperationUnknown rejects malformed UUIDs and does not invent a receipt after restart or expiry.
func TestConnectionOperationUnknown(t *testing.T) {
	handler := panelHandler("", "", nil, panelWrites{})
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/api/connections/operations/12345678-1234-4abc-8123-456789abcdef", "", http.StatusNotFound},
		{http.MethodGet, "/api/connections/operations/not-a-uuid", "", http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/connections/vpn/enabled", `{"enabled":false,"operationId":"bad"}`, http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/connections/vpn/enabled", `{"enabled":false,"operationId":""}`, http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/connections/vpn/enabled", `{"enabled":false,"operationId":null}`, http.StatusUnprocessableEntity},
	} {
		res := connectionOperationRequest(handler, tc.method, tc.path, tc.body)
		if res.Code != tc.status {
			t.Fatalf("%s %s status=%d want=%d body=%s", tc.method, tc.path, res.Code, tc.status, res.Body)
		}
	}
}

// TestConnectionOperationCapacity keeps running receipts and evicts only completed records when the bounded cache fills.
func TestConnectionOperationCapacity(t *testing.T) {
	receipts := &connectionOperationReceipts{}
	now := time.Now()
	ids := make([]string, connectionOperationLimit)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08x-1234-4abc-8123-456789abcdef", i)
		if _, started, err := receipts.begin(ids[i], "vpn", false, now); err != nil || !started {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	newID := "ffffffff-1234-4abc-8123-456789abcdef"
	if _, _, err := receipts.begin(newID, "vpn", true, now); connectionOperationStatus(err) != http.StatusServiceUnavailable {
		t.Fatalf("pending capacity error=%v", err)
	}
	receipts.complete(ids[0], http.StatusOK, now)
	if _, started, err := receipts.begin(newID, "vpn", true, now.Add(time.Second)); err != nil || !started {
		t.Fatalf("completed eviction: %v", err)
	}
	if _, ok := receipts.get(ids[0], now); ok {
		t.Fatal("completed receipt not evicted")
	}
	if got, ok := receipts.get(ids[1], now.Add(2*time.Hour)); !ok || got.State != panelmodel.ConnectionOperationPending {
		t.Fatal("pending receipt expired or evicted")
	}
	if len(receipts.entries) != connectionOperationLimit {
		t.Fatalf("receipt map grew to %d", len(receipts.entries))
	}
}

// TestConnectionOperationRetention drops expired terminal records while preserving exact public failure statuses.
func TestConnectionOperationRetention(t *testing.T) {
	receipts := &connectionOperationReceipts{}
	now := time.Now()
	operation := "12345678-1234-4abc-8123-456789abcdef"
	if _, _, err := receipts.begin(operation, "vpn", false, now); err != nil {
		t.Fatal(err)
	}
	receipts.complete(operation, http.StatusConflict, now)
	got, ok := receipts.get(operation, now.Add(connectionOperationRetention-time.Second))
	if !ok || got.State != panelmodel.ConnectionOperationFailed || got.Status != http.StatusConflict {
		t.Fatalf("terminal receipt=%#v exists=%v", got, ok)
	}
	if _, ok := receipts.get(operation, now.Add(connectionOperationRetention)); ok {
		t.Fatal("expired receipt retained")
	}
	if _, started, err := receipts.begin(operation, "vpn", true, now.Add(connectionOperationRetention)); err != nil || !started {
		t.Fatalf("expired UUID not reusable: %v", err)
	}
}
