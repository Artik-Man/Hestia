package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const healthy = `{"groups":[{"id":"ru","exits":["ru1"]},{"id":"fi","exits":["fi1","fi2"]}],"lists":[{"id":"fi-sites","group":"fi","masks":["*.example.org"]}],"healthy":{"ru1":true,"fi2":true}}`

// TestApply checks reserve selection, group blocking, and idempotence when the
// selector already has the desired target.
func TestApply(t *testing.T) {
	for _, tc := range []struct {
		name, previous, target string
		fi2, wantWrite         bool
	}{
		{name: "reserve", previous: "fi1", target: "fi2", fi2: true, wantWrite: true},
		{name: "outage", previous: "fi2", target: "deny", wantWrite: true},
		{name: "repeat", previous: "deny", target: "deny"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Decode([]byte(healthy))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Healthy["fi2"] = tc.fi2
			state, writes := tc.previous, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/proxies/fi" {
					t.Errorf("wrong path %q", r.URL.Path)
				}
				switch r.Method {
				case "GET":
					json.NewEncoder(w).Encode(selector{Type: "Selector", Now: state, All: []string{"fi1", "fi2", "deny"}})
				case "PUT":
					var update struct{ Name string }
					if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
						t.Error(err)
					}
					writes++
					state = update.Name
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("wrong method %s", r.Method)
				}
			}))
			defer server.Close()
			res, err := apply(context.Background(), server.Client(), server.URL, cfg, "api.example.org")
			if err != nil {
				t.Fatal(err)
			}
			if res.SelectorTarget != tc.target || state != tc.target || (writes == 1) != tc.wantWrite || writes > 1 {
				t.Fatalf("result %+v, state=%s, writes=%d", res, state, writes)
			}
		})
	}
}

// TestRejectBeforeMutation verifies that an invalid list binding is rejected
// before the controller contacts the selector API.
func TestRejectBeforeMutation(t *testing.T) {
	cfg, err := Decode([]byte(healthy))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Lists[0].Group = "missing"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Errorf("unexpected request %s", r.Method) }))
	defer server.Close()
	if _, err := apply(context.Background(), server.Client(), server.URL, cfg, "api.example.org"); err == nil {
		t.Fatal("accepted nonexistent group")
	}
}

// TestSelectorFailsBeforeWriteIfMembershipIsWrong verifies that a foreign exit
// in the live selector prevents a write even when the chosen exit is present.
func TestSelectorFailsBeforeWriteIfMembershipIsWrong(t *testing.T) {
	config, err := Decode([]byte(healthy))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected mutation: %s", r.Method)
		}
		// A known healthy tag is present, but the runtime selector also offers a foreign exit.
		json.NewEncoder(w).Encode(selector{Type: "Selector", Now: "fi1", All: []string{"fi1", "fi2", "deny", "ru1"}})
	}))
	defer server.Close()

	if _, err := apply(context.Background(), server.Client(), server.URL, config, "example.org"); err == nil {
		t.Fatal("foreign-group selector membership accepted")
	}
}

// TestUnconfirmedChangesAreNotReportedAsApplied checks that a rejected update,
// failed readback, or mismatched target returns an error without a success result.
func TestUnconfirmedChangesAreNotReportedAsApplied(t *testing.T) {
	config, err := Decode([]byte(healthy))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name          string
		putStatus     int
		readbackFails bool
	}{
		{name: "PUT rejected", putStatus: http.StatusBadRequest},
		{name: "PUT acknowledged but not applied", putStatus: http.StatusNoContent},
		{name: "readback unavailable", putStatus: http.StatusNoContent, readbackFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut {
					attempts++
					w.WriteHeader(tc.putStatus)
					return
				}
				if attempts != 0 && tc.readbackFails {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				json.NewEncoder(w).Encode(selector{Type: "Selector", Now: "fi1", All: []string{"fi1", "fi2", "deny"}})
			}))
			defer server.Close()
			got, err := apply(context.Background(), server.Client(), server.URL, config, "example.org")
			if err == nil || got != (Result{}) || attempts != 1 {
				t.Fatalf("result=%+v err=%v attempts=%d", got, err, attempts)
			}
		})
	}
}
