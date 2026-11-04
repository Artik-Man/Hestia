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

type fakeAWGWriter struct {
	connections map[string]panelmodel.AWGConnection
	profile     string
	checkErr    error
}

// Check records a temporary candidate string and returns a fake success without storing it.
func (f *fakeAWGWriter) Check(_ context.Context, profile string) (panelmodel.AWGCheckResult, error) {
	f.profile = profile
	return panelmodel.AWGCheckResult{Status: "handshake_confirmed", Message: "Временная проверка прошла", RouteReady: false}, f.checkErr
}

// Create stores fake public metadata while deliberately discarding the submitted secret profile.
func (f *fakeAWGWriter) Create(_ context.Context, request panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error) {
	if f.connections == nil {
		f.connections = map[string]panelmodel.AWGConnection{}
	}
	connection := panelmodel.AWGConnection{ID: request.ID, Group: request.Group, Priority: request.Priority, Status: "configured"}
	f.connections[request.ID] = connection
	return connection, nil
}

// Update replaces fake public metadata while discarding the submitted secret profile.
func (f *fakeAWGWriter) Update(_ context.Context, request panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error) {
	return f.Create(context.Background(), request)
}

// List returns the fake writer's current public metadata only.
func (f *fakeAWGWriter) List(context.Context) ([]panelmodel.AWGConnection, error) {
	connections := make([]panelmodel.AWGConnection, 0, len(f.connections))
	for _, connection := range f.connections {
		connections = append(connections, connection)
	}
	return connections, nil
}

// Delete removes one fake public record or reports that it was not found.
func (f *fakeAWGWriter) Delete(_ context.Context, id string) error {
	if _, ok := f.connections[id]; !ok {
		return context.Canceled
	}
	delete(f.connections, id)
	return nil
}

// TestAWGAPISecretSafeLifecycle checks check/create/list/delete and asserts secrets never appear in responses.
func TestAWGAPISecretSafeLifecycle(t *testing.T) {
	writer := &fakeAWGWriter{}
	handler := panelHandler("", "", nil, panelWrites{awg: writer})
	secret := "synthetic-private-secret-marker"
	profile := "[Interface]\nPrivateKey = " + secret + "\n"
	checkBody, _ := json.Marshal(panelmodel.AWGCheckRequest{Profile: profile})
	check := httptest.NewRecorder()
	handler.ServeHTTP(check, httptest.NewRequest(http.MethodPost, "/api/awg/check", strings.NewReader(string(checkBody))))
	if check.Code != http.StatusOK || strings.Contains(check.Body.String(), secret) || writer.profile != profile {
		t.Fatalf("unsafe or failed check response: %d %s", check.Code, check.Body.String())
	}
	saveBody, _ := json.Marshal(panelmodel.AWGSaveRequest{ID: "awg-one", Group: "fi", Priority: 1, Profile: profile})
	save := httptest.NewRecorder()
	handler.ServeHTTP(save, httptest.NewRequest(http.MethodPost, "/api/awg", strings.NewReader(string(saveBody))))
	if save.Code != http.StatusOK || strings.Contains(save.Body.String(), secret) || !strings.Contains(save.Body.String(), `"status":"configured"`) {
		t.Fatalf("unsafe or failed save response: %d %s", save.Code, save.Body.String())
	}
	update := httptest.NewRecorder()
	updateBody := `{"group":"ru","priority":2,"profile":` + string(mustJSON(t, profile)) + `}`
	handler.ServeHTTP(update, httptest.NewRequest(http.MethodPut, "/api/awg/awg-one", strings.NewReader(updateBody)))
	if update.Code != http.StatusOK || strings.Contains(update.Body.String(), secret) || !strings.Contains(update.Body.String(), `"group":"ru"`) {
		t.Fatalf("unsafe or failed update response: %d %s", update.Code, update.Body.String())
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/awg", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), secret) || !strings.Contains(list.Body.String(), "awg-one") {
		t.Fatalf("unsafe or failed list response: %d %s", list.Code, list.Body.String())
	}
	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, httptest.NewRequest(http.MethodDelete, "/api/awg/awg-one", nil))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("delete returned %d: %s", remove.Code, remove.Body.String())
	}
}

// mustJSON marshals a test value or fails the current test immediately.
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestAWGAPIFailsClosedWithoutWriter checks profile mutations are disabled when no privileged service exists.
func TestAWGAPIFailsClosedWithoutWriter(t *testing.T) {
	handler := panelHandler("", "", nil, panelWrites{})
	request := httptest.NewRequest(http.MethodGet, "/api/awg", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled list returned %d", response.Code)
	}
}

// TestAWGAPIRejectsPathAndOversizeInputs verifies route identifiers and profile body bounds.
func TestAWGAPIRejectsPathAndOversizeInputs(t *testing.T) {
	writer := &fakeAWGWriter{connections: map[string]panelmodel.AWGConnection{}}
	handler := panelHandler("", "", nil, panelWrites{awg: writer})
	delete := httptest.NewRecorder()
	handler.ServeHTTP(delete, httptest.NewRequest(http.MethodDelete, "/api/awg/%2e%2e", nil))
	if delete.Code != http.StatusNotFound {
		t.Fatalf("path traversal returned %d", delete.Code)
	}
	oversized := httptest.NewRecorder()
	body := `{"profile":"` + strings.Repeat("a", maxAWGRequestBytes) + `"}`
	handler.ServeHTTP(oversized, httptest.NewRequest(http.MethodPost, "/api/awg/check", strings.NewReader(body)))
	if oversized.Code != http.StatusRequestEntityTooLarge && oversized.Code != http.StatusUnprocessableEntity {
		t.Fatalf("oversized profile returned %d", oversized.Code)
	}
}
