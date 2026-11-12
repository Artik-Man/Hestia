package keeneticrci

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fixedHotspotTestToken string

// ReadToken returns the isolated test token without reading or retaining a real credential.
func (token fixedHotspotTestToken) ReadToken(context.Context) (string, error) {
	return string(token), nil
}

// TestMatchHotspotHostResolvesUniqueSourceWithoutRetainingOtherHostData ensures only one valid active source mapping is selected.
func TestMatchHotspotHostResolvesUniqueSourceWithoutRetainingOtherHostData(t *testing.T) {
	data := json.RawMessage(`{"host":[{"mac":"AA:BB:CC:DD:EE:01","ip":"192.0.2.10","active":true,"hostname":"ignored"},{"mac":"aa:bb:cc:dd:ee:02","ip":"192.0.2.11","active":true}]}`)
	mac, found, err := matchHotspotHost(data, netip.MustParseAddr("192.0.2.10"))
	if err != nil || !found || mac != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("unexpected client mapping mac=%q found=%v err=%v", mac, found, err)
	}
}

// TestMatchHotspotHostRejectsAmbiguousOrInvalidSourceMappings prevents uncertain IP-to-client joins.
func TestMatchHotspotHostRejectsAmbiguousOrInvalidSourceMappings(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.10")
	for _, data := range []json.RawMessage{
		json.RawMessage(`{"host":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.0.2.10","active":true},{"mac":"aa:bb:cc:dd:ee:02","ip":"192.0.2.10","active":true}]}`),
		json.RawMessage(`{"host":[{"mac":"not-a-mac","ip":"192.0.2.10","active":true}]}`),
	} {
		if _, found, err := matchHotspotHost(data, address); err == nil || found {
			t.Fatalf("ambiguous or invalid mapping accepted: found=%v err=%v", found, err)
		}
	}
	if _, found, err := matchHotspotHost(json.RawMessage(`{"host":[]}`), address); err != nil || found {
		t.Fatalf("missing client mapping should be a clean miss: found=%v err=%v", found, err)
	}
	if _, found, err := matchHotspotHost(json.RawMessage(`{"host":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.0.2.10","active":false}]}`), address); err != nil || found {
		t.Fatalf("inactive client mapping should not resolve: found=%v err=%v", found, err)
	}
}

// TestMatchHotspotHostPolicyAcceptsObservedSettingsShapesAndReturnsOnlyPolicy verifies supported host-map encodings.
func TestMatchHotspotHostPolicyAcceptsObservedSettingsShapesAndReturnsOnlyPolicy(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	for _, data := range []json.RawMessage{
		json.RawMessage(`{"host":{"AA:BB:CC:DD:EE:01":{"policy":"Policy2"}}}`),
		json.RawMessage(`{"host":[{"mac":"aa:bb:cc:dd:ee:01","policy":"Policy2"}]}`),
		json.RawMessage(`[{"access":"Internet","mac":"aa:bb:cc:dd:ee:01","permit":["OpkgTun0"],"policy":"Policy2"}]`),
	} {
		policy, explicit, err := matchHotspotHostPolicy(data, mac)
		if err != nil || !explicit || policy != "Policy2" {
			t.Fatalf("unexpected assigned policy=%q explicit=%v err=%v", policy, explicit, err)
		}
	}
}

// TestMatchHotspotHostPolicyLeavesMissingAndInheritedAssignmentUnresolved avoids inferring a client policy from an operator hint.
func TestMatchHotspotHostPolicyLeavesMissingAndInheritedAssignmentUnresolved(t *testing.T) {
	mac := "aa:bb:cc:dd:ee:01"
	for _, data := range []json.RawMessage{
		json.RawMessage(`{"host":{}}`),
		json.RawMessage(`{"host":{"aa:bb:cc:dd:ee:01":{}}}`),
		json.RawMessage(`[{"mac":"aa:bb:cc:dd:ee:01","permit":["OpkgTun0"]}]`),
	} {
		if policy, explicit, err := matchHotspotHostPolicy(data, mac); err != nil || explicit || policy != "" {
			t.Fatalf("unresolved assignment claimed policy=%q explicit=%v err=%v", policy, explicit, err)
		}
	}
	if _, _, err := matchHotspotHostPolicy(json.RawMessage(`{"host":{"aa:bb:cc:dd:ee:01":{"policy":"not-policy"}}}`), mac); err == nil {
		t.Fatal("invalid policy identity accepted")
	}
	if _, _, err := matchHotspotHostPolicy(json.RawMessage(`{"host":{"aa:bb:cc:dd:ee:01":{"policy":"Policy12345678901"}}}`), mac); err == nil {
		t.Fatal("policy identity exceeding the stored schema was accepted")
	}
}

// TestReadClientPolicyAssignmentUsesOnlyReadOperationsAndRedactsHostIdentity verifies source mapping and endpoint scope.
func TestReadClientPolicyAssignmentUsesOnlyReadOperationsAndRedactsHostIdentity(t *testing.T) {
	client, err := NewClient(Config{BaseURL: "http://127.0.0.1:79", TokenSource: fixedHotspotTestToken("test-only-token"), Timeout: time.Second, MaxResponseBytes: 4096})
	if err != nil {
		t.Fatalf("create RCI test client: %v", err)
	}
	var requests []string
	client.httpClient.Transport = hotspotTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.Header.Get(tokenHeader) != "test-only-token" {
			t.Errorf("unexpected RCI request method=%q token=%q", r.Method, r.Header.Get(tokenHeader))
		}
		requests = append(requests, r.URL.Path)
		body := `{"host":[{"mac":"aa:bb:cc:dd:ee:01","ip":"192.0.2.10","active":true,"hostname":"ignored"}]}`
		switch r.URL.Path {
		case hotspotHostsConfigPath:
			body = `{"host":{"aa:bb:cc:dd:ee:01":{"policy":"Policy2"}}}`
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	assignment, err := client.ReadClientPolicyAssignment(context.Background(), "192.0.2.10")
	if err != nil || !assignment.Found || !assignment.Explicit || assignment.PolicyKey != "Policy2" {
		t.Fatalf("unexpected assignment %+v err=%v", assignment, err)
	}
	if len(requests) != 2 || requests[0] != hotspotHostsRuntimePath || requests[1] != hotspotHostsConfigPath {
		t.Fatalf("unexpected read sequence: %v", requests)
	}
}

// hotspotTestRoundTripper supplies local canned RCI responses without opening a socket.
type hotspotTestRoundTripper func(*http.Request) (*http.Response, error)

// RoundTrip returns one canned response for an RCI unit test and never accesses a network.
func (roundTrip hotspotTestRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
