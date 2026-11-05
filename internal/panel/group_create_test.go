package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// TestCreateGroupHTTP checks that only valid IDs reach an enabled writer and success follows its confirmation.
func TestCreateGroupHTTP(t *testing.T) {
	for _, tc := range []struct {
		body     string
		enabled  bool
		conflict bool
		status   int
	}{
		{`{"id":"work-2"}`, true, false, 201},
		{`{"id":"work-2"}`, true, true, 409},
		{`{"id":"work-2"}`, false, false, 503},
		{`{"id":"deny"}`, true, false, 422},
		{`{"id":"Work"}`, true, false, 422},
		{`{"id":"work","exits":["exit"]}`, true, false, 422},
		{`{}`, true, false, 422},
	} {
		var writes panelWrites
		called := false
		if tc.enabled {
			writes.createGroup = func(_ context.Context, group panelmodel.GroupCreateRequest) (panelmodel.GroupIdentifier, error) {
				called = true
				if group.ID == nil || *group.ID != "work-2" {
					t.Fatalf("unexpected ID %v", group.ID)
				}
				if tc.conflict {
					return panelmodel.GroupIdentifier{}, huma.Error409Conflict("conflict")
				}
				return panelmodel.GroupIdentifier{ID: *group.ID}, nil
			}
		}
		req := httptest.NewRequest(http.MethodPost, "/api/groups", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, req)
		if res.Code != tc.status || called != (tc.status == 201 || tc.status == 409) {
			t.Errorf("%s: %d, called %v, response %s", tc.body, res.Code, called, res.Body)
		}
		if res.Code == 201 {
			var result panelmodel.GroupIdentifier
			if json.Unmarshal(res.Body.Bytes(), &result) != nil || result.ID != "work-2" {
				t.Errorf("unexpected result %s", res.Body)
			}
		}
	}
}

// TestGroupDisplayNamesHTTP checks stable IDs, Unicode names, and rejection of ambiguous or invalid edits.
func TestGroupDisplayNamesHTTP(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/api/groups", `{"name":"Домашняя сеть"}`, 201},
		{"PUT", "/api/groups/default", `{"name":"Домашняя сеть"}`, 200},
		{"POST", "/api/groups", `{"name":"Домашняя сеть","id":"default"}`, 422},
		{"PUT", "/api/groups/default", `{"name":""}`, 422},
		{"PUT", "/api/groups/deny", `{"name":"Домашняя сеть"}`, 422},
	} {
		calls := 0
		writes := panelWrites{
			createGroup: func(_ context.Context, in panelmodel.GroupCreateRequest) (panelmodel.GroupIdentifier, error) {
				calls++
				return panelmodel.GroupIdentifier{ID: "g-example", Name: *in.Name}, nil
			},
			renameGroup: func(_ context.Context, id, name string) error {
				calls++
				if id != "default" || name != "Домашняя сеть" {
					t.Fatalf("unexpected rename %q %q", id, name)
				}
				return nil
			},
		}
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, req)
		if res.Code != tc.status || (calls == 1) != (tc.status < 300) {
			t.Errorf("%s %s: status %d calls %d %s", tc.method, tc.path, res.Code, calls, res.Body)
		}
		if tc.status < 300 {
			var got panelmodel.GroupIdentifier
			if json.Unmarshal(res.Body.Bytes(), &got) != nil || got.Name != "Домашняя сеть" || (tc.method == "POST" && got.ID != "g-example") || (tc.method == "PUT" && got.ID != "default") {
				t.Errorf("unexpected response: %s", res.Body)
			}
		}
	}
}

// TestDirectRenameEndpoint confirms stable routing identity, catalog response type and input validation.
func TestDirectRenameEndpoint(t *testing.T) {
	calls := 0
	handler := panelHandler("", "", nil, panelWrites{renameDirect: func(_ context.Context, id, name string) error {
		calls++
		if id != "wan" || name != "Провайдер" {
			t.Fatal("wrong name or routing ID")
		}
		return nil
	}})
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"name":"Провайдер"}`, http.StatusOK}, {`{"name":" invalid"}`, http.StatusUnprocessableEntity},
	} {
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodPut, "/api/connections/wan/name", strings.NewReader(tc.body)))
		if res.Code != tc.status {
			t.Fatalf("status %d: %s", res.Code, res.Body.String())
		}
		if tc.status == http.StatusOK && !strings.Contains(res.Body.String(), `"type":"direct"`) {
			t.Fatal("missing direct type")
		}
	}
	if calls != 1 {
		t.Fatal("invalid request reached helper")
	}
}
