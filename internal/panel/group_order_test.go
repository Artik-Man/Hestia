package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// TestGroupOrderHTTP verifies disabled mode, helper conflicts and confirmed topology through the registered HTTP API.
func TestGroupOrderHTTP(t *testing.T) {
	body := `{"expected":[{"id":"fi","exits":["first","second"]}],"groups":[{"id":"fi","exits":["second","first"]}]}`
	group := []panelmodel.OrderedGroup{{ID: "fi", Exits: []string{"second", "first"}}}
	cases := []struct {
		status int
		write  orderWriter
	}{
		{503, nil},
		{409, func(context.Context, panelmodel.GroupOrderChange) error { return huma.Error409Conflict("conflict") }},
		{200, func(_ context.Context, change panelmodel.GroupOrderChange) error {
			if !reflect.DeepEqual(change.Groups, group) || len(change.Expected) != 1 || change.Expected[0].Exits[0] != "first" {
				t.Fatalf("unexpected change: %+v", change)
			}
			return nil
		}},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodPut, "/api/group-order", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		panelHandler("", "", nil, panelWrites{order: tc.write}).ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("want %d, got %d: %s", tc.status, w.Code, w.Body)
		}
		if tc.status == 200 {
			var result panelmodel.AppliedOrder
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !reflect.DeepEqual(result.Groups, group) {
				t.Fatalf("invalid applied order: %s", w.Body)
			}
		}
	}
}

// TestGroupOrderRejectsMalformedArrays prevents element-by-element errors from amplifying a bad ordering request.
func TestGroupOrderRejectsMalformedArrays(t *testing.T) {
	body := `{"expected":[` + strings.Repeat("{},", 9999) + `{}],"groups":[]}`
	handler := panelHandler("", "", nil, panelWrites{})
	for _, tc := range []struct {
		body   string
		status int
	}{
		{body, 422}, {strings.Repeat(" ", 65537), 413},
		{`{"groups":[],"expected":[],"extra":true}`, 422},
	} {
		r := httptest.NewRequest(http.MethodPut, "/api/group-order", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status || w.Body.Len() > 2048 {
			t.Errorf("got status %d (%d response bytes), want %d", w.Code, w.Body.Len(), tc.status)
		}
	}
}
