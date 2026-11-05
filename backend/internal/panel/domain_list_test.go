package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// TestDomainListWriteDisabled verifies that domain-list writes are registered but unavailable on a read-only panel.
func TestDomainListWriteDisabled(t *testing.T) {
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/api/domain-lists", `{"name":"Новости","group":"","masks":["*.example.org"]}`},
		{"PUT", "/api/domain-lists/legacy", `{"expected":{"id":"legacy","group":"","masks":[],"enabled":false},"list":{"name":"Новости","group":"","masks":["*.example.org"]}}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, panelWrites{}).ServeHTTP(res, req)
		if res.Code != 503 {
			t.Errorf("expected disabled operation: %d %s", res.Code, res.Body)
		}
	}
}

// TestDomainListWrites verifies valid create/update responses, stale edits and validation at the HTTP boundary.
func TestDomainListWrites(t *testing.T) {
	const createBody = `{"name":"Новости","group":"fi","masks":["*.example.org"]}`
	const expected = `{"id":"legacy","group":"","masks":[],"enabled":false}`
	const updateBody = `{"expected":` + expected + `,"list":` + createBody + `}`
	for _, tc := range []struct {
		method, path, body string
		status             int
		conflict           bool
	}{
		{"POST", "/api/domain-lists", createBody, 201, false},
		{"PUT", "/api/domain-lists/legacy", updateBody, 200, false},
		{"PUT", "/api/domain-lists/legacy", updateBody, 409, true},
		{"PUT", "/api/domain-lists/other", updateBody, 422, false},
		{"PUT", "/api/domain-lists/legacy", createBody, 422, false},
		{"POST", "/api/domain-lists", `{"name":"Тест","masks":[]}`, 422, false},
		{"POST", "/api/domain-lists", `{"name":"Тест","group":"","masks":["example.org"]}`, 422, false},
		{"POST", "/api/domain-lists", `{"name":"Тест","group":"","masks":null}`, 422, false},
	} {
		called := false
		saved := panelmodel.RuleList{ID: "legacy", Name: "Новости", Group: "fi", Masks: []string{"*.example.org"}, Enabled: true}
		write := func(_ context.Context, values panelmodel.DomainListValues) (panelmodel.RuleList, error) {
			called = true
			if values.Name != saved.Name || values.Group != saved.Group || !slices.Equal(values.Masks, saved.Masks) {
				t.Fatalf("unexpected values %+v", values)
			}
			if tc.conflict {
				return panelmodel.RuleList{}, huma.Error409Conflict("stale")
			}
			return saved, nil
		}
		writes := panelWrites{createDomainList: write, updateDomainList: func(ctx context.Context, id string, change panelmodel.DomainListUpdate) (panelmodel.RuleList, error) {
			if id != "legacy" || change.Expected.ID != id || change.Expected.Enabled || change.Expected.Group != "" || len(change.Expected.Masks) != 0 {
				t.Fatalf("unexpected precondition %+v", change.Expected)
			}
			return write(ctx, change.List)
		}}
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, req)
		if res.Code != tc.status || called != (tc.status < 300 || tc.conflict) {
			t.Errorf("%s %s: status=%d called=%t response=%s", tc.method, tc.body, res.Code, called, res.Body)
			continue
		}
		if tc.status < 300 {
			var result panelmodel.RuleList
			if json.Unmarshal(res.Body.Bytes(), &result) != nil || !reflect.DeepEqual(result, saved) {
				t.Errorf("unexpected confirmation: %s", res.Body)
			}
		}
	}
}

// TestDomainListConfirmation rejects missing or inconsistent acknowledgments from the privileged helper.
func TestDomainListConfirmation(t *testing.T) {
	values := panelmodel.DomainListValues{Name: "Тест", Group: "fi", Masks: []string{"*.example.org"}}
	for _, data := range []string{`{}`, `{"id":"wrong","name":"Тест","group":"fi","enabled":true,"masks":["*.example.org"]}`, `{"id":"list","name":"Тест","group":"fi","enabled":false,"masks":["*.example.org"]}`, `{"id":"list","name":"Тест","group":"fi","enabled":true,"masks":[]}`} {
		if _, err := confirmedDomainList([]byte(data), "list", values); err == nil {
			t.Errorf("accepted incomplete response %s", data)
		}
	}
}

// TestDomainListDeleteRoute verifies exact deletion preconditions, confirmed status and read-only/conflict failures.
func TestDomainListDeleteRoute(t *testing.T) {
	const original = `{"id":"legacy","group":"","enabled":false,"masks":[]}`
	for _, tc := range []struct {
		id, body string
		status   int
		call     bool
	}{
		{"legacy", original, 204, true},
		{"legacy", original, 409, true},
		{"legacy", original, 503, false},
		{"other", original, 422, false},
		{"legacy", `{"id":"legacy"}`, 422, false},
	} {
		var called bool
		var writes panelWrites
		if tc.status != 503 {
			writes.deleteDomainList = func(_ context.Context, expected panelmodel.RuleList) error {
				called = true
				if !reflect.DeepEqual(expected, panelmodel.RuleList{ID: "legacy", Masks: []string{}}) {
					t.Fatalf("unexpected delete precondition: %+v", expected)
				}
				if tc.status == 409 {
					return huma.Error409Conflict("stale list")
				}
				return nil
			}
		}
		req := httptest.NewRequest("DELETE", "/api/domain-lists/"+tc.id, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, req)
		if res.Code != tc.status || called != tc.call || res.Code == 204 && res.Body.Len() != 0 {
			t.Fatalf("DELETE %s: status=%d called=%t body=%s", tc.id, res.Code, called, res.Body)
		}
	}
}
