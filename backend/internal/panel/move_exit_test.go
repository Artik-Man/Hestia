package panel

import (
	"context"
	"encoding/json"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"

	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMoveExitValidation requires an enabled privileged writer and both group IDs before dispatching a move.
func TestMoveExitValidation(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"expectedGroup":"home","group":"work","priority":2}`, 503},
		{`{"group":"work","priority":2}`, 422},
		{`{"expectedGroup":"home","group":"work"}`, 422},
		{`{"expectedGroup":"home","group":"work","priority":0}`, 422},
		{`{"expectedGroup":"home","group":"deny","priority":2}`, 422},
		{`{"expectedGroup":"home","group":"work","priority":2,"profile":"unexpected"}`, 422},
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/connections/awg-home/group", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, panelWrites{}).ServeHTTP(res, req)
		if res.Code != tc.status {
			t.Errorf("%s: got %d want %d", tc.body, res.Code, tc.status)
		}
	}
}

// TestMoveExitConfirmation verifies that the source precondition reaches the writer and a conflict cannot be echoed as success.
func TestMoveExitConfirmation(t *testing.T) {
	const source = "home"
	const id = "12345678-1234-4abc-8abc-123456789abc"
	for _, tc := range []struct {
		expected string
		status   int
	}{{source, 200}, {"former", 409}} {
		writes := panelWrites{moveExit: func(_ context.Context, change panelmodel.ExitMoveCommand) error {
			if change.ID != id || change.Group != "work" || change.ExpectedGroup != tc.expected || change.Priority != 2 {
				t.Fatalf("unexpected request %+v", change)
			}
			if change.ExpectedGroup != source {
				return huma.Error409Conflict("connection group changed")
			}
			return nil
		}}
		req := httptest.NewRequest(http.MethodPut, "/api/connections/"+id+"/group", strings.NewReader(`{"expectedGroup":"`+tc.expected+`","group":"work","priority":2}`))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, req)
		if res.Code != tc.status {
			t.Fatalf("status %d, want %d", res.Code, tc.status)
		}
		if res.Code == 200 {
			var got panelmodel.ExitGroupAssignment
			if json.Unmarshal(res.Body.Bytes(), &got) != nil || got.ID != id || got.Group != "work" || got.Priority != 2 {
				t.Errorf("wrong assignment: %s", res.Body)
			}
		}
	}
}
