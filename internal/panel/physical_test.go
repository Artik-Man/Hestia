package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestPhysicalAPI verifies the HTTP methods, credential-free responses, redaction of parse errors and fixed gateway commands.
func TestPhysicalAPI(t *testing.T) {
	mode := ""
	h := panelHandler("", "", nil, panelWrites{physical: func(_ context.Context, op string, in, out any) error {
		mode = op
		if op == "-physical-list" {
			*(out.(*panelmodel.PhysicalInventory)) = panelmodel.PhysicalInventory{Interfaces: []panelmodel.PhysicalInterface{}, WifiProfiles: []panelmodel.WifiConnection{}}
		}
		return nil
	}})
	id := "ea071db0-34e9-4e3c-931e-46465a754691"
	body := `{"interfaceName":"wlan0","ssid":"Lab","band":"5","security":"wpa-psk","password":"private-pass"}`
	for _, tc := range []struct {
		method, path, body, mode string
		code                     int
	}{
		{"GET", "/api/physical-connections", "", "-physical-list", 200},
		{"POST", "/api/wifi-connections", body, "-wifi-create", 204},
		{"PUT", "/api/wifi-connections/" + id, body, "-wifi-save", 204},
		{"DELETE", "/api/wifi-connections/" + id, "", "-wifi-delete", 204},
		{"PUT", "/api/wifi-connections/" + id, strings.Replace(body, `"5"`, `"6"`, 1), "", 422},
		{"POST", "/api/wifi-connections", body[:len(body)-1], "", http.StatusBadRequest},
	} {
		mode = ""
		res := httptest.NewRecorder()
		h.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if res.Code != tc.code || mode != tc.mode || strings.Contains(res.Body.String(), "private-pass") {
			t.Fatalf("%s %s: status %d mode %q", tc.method, tc.path, res.Code, mode)
		}
	}
}

// TestWifiDisconnect lets started writes finish within a bounded recovery window while cancelling an outstanding inventory read.
func TestWifiDisconnect(t *testing.T) {
	const path = "/api/wifi-connections"
	const id = "/ea071db0-34e9-4e3c-931e-46465a754691"
	const body = `{"interfaceName":"wlan0","ssid":"Lab","band":"5","security":"open"}`
	for _, tc := range []struct{ method, url, body string }{
		{"POST", path, body}, {"PUT", path + id, body}, {"DELETE", path + id, ""}, {"GET", "/api/physical-connections", ""},
	} {
		request, cancel := context.WithCancel(context.Background())
		called := false
		h := panelHandler("", "", nil, panelWrites{physical: func(ctx context.Context, _ string, _ any, _ any) error {
			called = true
			cancel()
			if tc.method == "GET" {
				if ctx.Err() != context.Canceled {
					t.Fatal("inventory did not inherit disconnect")
				}
				return ctx.Err()
			}
			deadline, ok := ctx.Deadline()
			remaining := time.Until(deadline)
			if ctx.Err() != nil || !ok || remaining <= 155*time.Second || remaining > 3*time.Minute {
				t.Fatalf("%s helper cannot complete bounded rollback", tc.method)
			}
			return nil
		}})
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body)).WithContext(request))
		cancel()
		if !called {
			t.Fatalf("%s helper not reached", tc.method)
		}
	}
}
