package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/google/uuid"
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
	connection := panelmodel.AWGConnection{Name: request.Name, ID: request.ID, Group: request.Group, Priority: int(request.Priority), Status: "configured"}
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
	saveBody, _ := json.Marshal(panelmodel.AWGCreateRequest{Name: "Офис № 1", Group: "fi", Priority: 1, Profile: profile})
	save := httptest.NewRecorder()
	handler.ServeHTTP(save, httptest.NewRequest(http.MethodPost, "/api/awg", strings.NewReader(string(saveBody))))
	if save.Code != http.StatusOK || strings.Contains(save.Body.String(), secret) || !strings.Contains(save.Body.String(), `"status":"configured"`) {
		t.Fatalf("unsafe or failed save response: %d %s", save.Code, save.Body.String())
	}
	var created panelmodel.AWGConnection
	if json.Unmarshal(save.Body.Bytes(), &created) != nil || created.Name != "Офис № 1" {
		t.Fatal("missing display name")
	}
	id, err := uuid.Parse(created.ID)
	if err != nil || id.Version() != 4 || id.String() != created.ID {
		t.Fatal("missing server assigned UUID")
	}
	update := httptest.NewRecorder()
	updateBody := `{"name":"Резерв","group":"ru","priority":2,"profile":` + string(mustJSON(t, profile)) + `}`
	handler.ServeHTTP(update, httptest.NewRequest(http.MethodPut, "/api/awg/"+created.ID, strings.NewReader(updateBody)))
	if update.Code != http.StatusOK || strings.Contains(update.Body.String(), secret) || !strings.Contains(update.Body.String(), `"group":"ru"`) {
		t.Fatalf("unsafe or failed update response: %d %s", update.Code, update.Body.String())
	}
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/awg", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), secret) || !strings.Contains(list.Body.String(), created.ID) || !strings.Contains(list.Body.String(), "Резерв") {
		t.Fatalf("unsafe or failed list response: %d %s", list.Code, list.Body.String())
	}
	remove := httptest.NewRecorder()
	handler.ServeHTTP(remove, httptest.NewRequest(http.MethodDelete, "/api/awg/"+created.ID, nil))
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

// ReadProfile returns synthetic editor data for one fixture connection or the helper's missing-ID status.
func (f *fakeAWGWriter) ReadProfile(_ context.Context, id string) (panelmodel.AWGConnectionProfile, error) {
	connection, ok := f.connections[id]
	if !ok {
		return panelmodel.AWGConnectionProfile{}, awgHTTPFailure{status: http.StatusNotFound}
	}
	return panelmodel.AWGConnectionProfile{Name: connection.Name, ID: connection.ID, Group: connection.Group, Priority: connection.Priority, Profile: f.profile}, nil
}

// TestAWGEditorRead checks that only a valid per-ID response contains the full normalized secret and forbids caching.
func TestAWGEditorRead(t *testing.T) {
	const profile = "[Interface]\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n[Peer]\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n"
	parsed, err := awg.Parse([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeAWGWriter{connections: map[string]panelmodel.AWGConnection{"vpn": {Name: "Офис", ID: "vpn", Group: "home", Priority: 2}}, profile: string(parsed.SecretConfig)}
	handler := panelHandler("", "", nil, panelWrites{awg: writer})
	for _, scenario := range []struct {
		path   string
		status int
	}{{"vpn", 200}, {"missing", 404}, {"BAD", 404}} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/awg/"+scenario.path, nil))
		if w.Code != scenario.status || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("wrong response to %s: %d", scenario.path, w.Code)
		}
		if w.Code == http.StatusOK {
			var got panelmodel.AWGConnectionProfile
			if json.Unmarshal(w.Body.Bytes(), &got) != nil || got.Profile != writer.profile || got.ID != "vpn" || got.Priority != 2 {
				t.Fatal("incomplete editor profile")
			}
		} else if strings.Contains(w.Body.String(), "PrivateKey") {
			t.Fatal("key in failed read")
		}
	}
	writer.profile = "PrivateKey = secret-should-not-leak"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/awg/vpn", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "secret-should-not-leak") {
		t.Fatal("malformed helper response escaped validation")
	}
}

// Underlays returns a synthetic public transport exit for HTTP contract tests.
func (*fakeAWGWriter) Underlays(context.Context) ([]panelmodel.AWGUnderlayCandidate, error) {
	return []panelmodel.AWGUnderlayCandidate{{ID: "uplink", Type: "direct"}}, nil
}

// TestAWGUnderlayWireContract ensures the helper wire format distinguishes explicit automatic mode from omission by older clients.
func TestAWGUnderlayWireContract(t *testing.T) {
	for _, test := range []struct {
		choices []string
		wire    string
	}{{nil, ""}, {[]string{}, "[]"}, {[]string{"b", "a"}, `["b","a"]`}} {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(mustJSON(t, panelmodel.AWGSaveRequest{Underlays: test.choices}), &fields); err != nil || string(fields["underlays"]) != test.wire {
			t.Fatal("underlay preferences lost on helper boundary")
		}
	}
	handler := panelHandler("", "", nil, panelWrites{awg: &fakeAWGWriter{}})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/awg-underlays", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"type":"direct"`) {
		t.Fatal("missing public underlay choices")
	}
}

// TestAWGOptionalPlacement accepts omitted placement and rejects explicitly invalid fields without returning profile material.
func TestAWGOptionalPlacement(t *testing.T) {
	handler := panelHandler("", "", nil, panelWrites{awg: &fakeAWGWriter{}})
	for _, tc := range []struct {
		method, path, body string
		ok                 bool
	}{
		{"POST", "/api/awg", `{"name":"Офис","group":"fi","profile":"sensitive-profile"}`, true},
		{"PUT", "/api/awg/wg", `{"profile":"sensitive-profile"}`, true},
		{"PUT", "/api/awg/wg", `{"priority":0,"profile":"sensitive-profile"}`, false},
		{"PUT", "/api/awg/wg", `{"group":null,"profile":"sensitive-profile"}`, false},
		{"POST", "/api/awg", `{"id":"wg","profile":"sensitive-profile"}`, false},
		{"POST", "/api/awg", `{"id":"wg","group":"fi","profile":"sensitive-profile"}`, false},
		{"POST", "/api/awg", `{"name":" ","group":"fi","profile":"sensitive-profile"}`, false},
		{"POST", "/api/awg", `{"id":"chosen","name":"Офис","group":"fi","profile":"sensitive-profile"}`, false},
		{"PUT", "/api/awg/wg", `{"name":"","profile":"sensitive-profile"}`, false},
	} {
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if (result.Code == http.StatusOK) != tc.ok || strings.Contains(result.Body.String(), "sensitive-profile") {
			t.Fatalf("unexpected %s response: %d %s", tc.method, result.Code, result.Body.String())
		}
	}
}
