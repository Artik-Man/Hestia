package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

// TestDeleteGroupHTTP checks confirmation, conflicts, absent groups and that malformed IDs never reach the helper.
func TestDeleteGroupHTTP(t *testing.T) {
	for _, tc := range []struct {
		id      string
		enabled bool
		err     error
		status  int
	}{
		{"g-work", true, nil, 204},
		{"g-work", true, huma.Error409Conflict("group is in use"), 409},
		{"g-work", true, huma.Error404NotFound("group is absent"), 404},
		{"g-work", false, nil, 503},
		{"deny", true, nil, 422},
	} {
		var writes panelWrites
		called := false
		if tc.enabled {
			writes.deleteGroup = func(_ context.Context, id string) error {
				called = true
				if id != "g-work" {
					t.Fatalf("unexpected deletion of %q", id)
				}
				return tc.err
			}
		}
		res := httptest.NewRecorder()
		panelHandler("", "", nil, writes).ServeHTTP(res, httptest.NewRequest(http.MethodDelete, "/api/groups/"+tc.id, nil))
		if res.Code != tc.status || called != (tc.enabled && tc.id == "g-work") || (res.Code == 204 && res.Body.Len() != 0) {
			t.Errorf("%s: status %d called %v body %s", tc.id, res.Code, called, res.Body)
		}
	}
}
