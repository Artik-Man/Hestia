package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestBindingConfirmation checks that 200 follows the writer's confirmation and includes the applied group.
func TestBindingConfirmation(t *testing.T) {
	started := make(chan panelmodel.BindingChange, 1)
	confirm := make(chan struct{})
	write := func(_ context.Context, change panelmodel.BindingChange) error {
		started <- change
		<-confirm
		return nil
	}
	handler := panelHandler("", "", nil, panelWrites{binding: write})
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	req := httptest.NewRequest(http.MethodPut, "/api/list-binding", strings.NewReader(`{"listId":"media","expectedGroup":"fi","group":"ru"}`))
	req.Header.Set("Content-Type", "application/json")
	go func() {
		handler.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case change := <-started:
		if change != (panelmodel.BindingChange{ListID: "media", ExpectedGroup: "fi", Group: "ru"}) {
			close(confirm)
			t.Fatalf("unexpected helper input %+v", change)
		}
	case <-done:
		t.Fatalf("completed without calling writer: %d %s", rec.Code, rec.Body)
	}
	select {
	case <-done:
		t.Fatal("responded before confirmation")
	default:
	}
	close(confirm)
	<-done
	var applied panelmodel.AppliedBinding
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &applied) != nil || applied != (panelmodel.AppliedBinding{ListID: "media", Group: "ru"}) {
		t.Fatalf("unconfirmed response: %d %s", rec.Code, rec.Body)
	}
}

// TestBindingAccess checks disabled mode, field presence and cross-site rejection before execution.
func TestBindingAccess(t *testing.T) {
	for _, test := range []struct {
		body, site string
		status     int
	}{
		{`{"listId":"list","expectedGroup":"fi","group":""}`, "", 503},
		{`{"listId":"list","expectedGroup":"fi"}`, "", 422},
		{`{"listId":"list","expectedGroup":"fi","group":""}`, "cross-site", 403},
	} {
		r := httptest.NewRequest("PUT", "/api/list-binding", strings.NewReader(test.body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Sec-Fetch-Site", test.site)
		w := httptest.NewRecorder()
		panelHandler("", "", nil, panelWrites{}).ServeHTTP(w, r)
		if w.Code != test.status {
			t.Errorf("got %d want %d: %s", w.Code, test.status, w.Body)
		}
	}
}
