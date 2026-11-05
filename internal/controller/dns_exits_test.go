package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// TestDNSExitsUsesLiveSelector verifies explicit masks, live reserve selection and fail-closed behavior without touching the installed controller.
func TestDNSExitsUsesLiveSelector(t *testing.T) {
	for _, tc := range []struct {
		name, domain, target       string
		unhealthy, foreign, reject bool
		want, groups               []string
	}{
		{name: "ordinary parallel candidates", domain: "other.example", target: "fi2", want: []string{"ru1", "fi2"}, groups: []string{"ru", "fi"}},
		{name: "explicit mask uses live reserve", domain: "api.example.org", target: "fi2", want: []string{"fi2"}, groups: []string{"fi"}},
		{name: "explicit deny with RU healthy", domain: "example.org", target: "deny", groups: []string{"fi"}},
		{name: "service records preserve explicit group", domain: "client._sip._TCP.example.org.", target: "fi2", want: []string{"fi2"}, groups: []string{"fi"}},
		{name: "service records respect denied group", domain: "_service._tcp.example.org", target: "deny", groups: []string{"fi"}},
		{name: "root query only uses live allowed groups", domain: ".", target: "deny", want: []string{"ru1"}, groups: []string{"ru", "fi"}},
		{name: "canonical root query uses live allowed groups", domain: "", target: "fi2", want: []string{"ru1", "fi2"}, groups: []string{"ru", "fi"}},
		{name: "service owner without hostname suffix", domain: "_sip._tcp.", target: "fi2", reject: true},
		{name: "empty interior label", domain: "_sip..example.org", target: "fi2", reject: true},
		{name: "escaped label cannot fall through", domain: `script\.evil._tcp.example.org`, target: "fi2", reject: true},
		{name: "Unicode label before service owner", domain: "K._tcp.example.org", target: "fi2", reject: true},
		{name: "control byte", domain: "bad\n._tcp.example.org", target: "fi2", reject: true},
		{name: "unhealthy FI with RU healthy", domain: "example.org", target: "fi2", unhealthy: true, groups: []string{"fi"}},
		{name: "foreign membership on FI", domain: "example.org", target: "fi2", foreign: true, groups: []string{"fi"}},
		{name: "unrestricted survives misconfigured FI", domain: "other.example", target: "fi2", foreign: true, want: []string{"ru1"}, groups: []string{"ru", "fi"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CheckSnapshot([]byte(healthy))
			if err != nil {
				t.Fatal(err)
			}
			cfg.Healthy["fi2"] = !tc.unhealthy
			var visited []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				group := strings.TrimPrefix(r.URL.Path, "/proxies/")
				if r.Method != http.MethodGet {
					t.Errorf("unexpected mutation %s", r.Method)
				}
				visited = append(visited, group)
				state := selector{Type: "Selector", Now: "ru1", All: []string{"ru1", "deny"}}
				if group == "fi" {
					state.Now = tc.target
					state.All = []string{"fi1", "fi2", "deny"}
					if tc.foreign {
						state.All = append(state.All, "ru1")
					}
				}
				if err := json.NewEncoder(w).Encode(state); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			got, err := dnsExits(context.Background(), server.Client(), server.URL, cfg, tc.domain)
			if (err != nil) != tc.reject || !slices.Equal(got, tc.want) || !slices.Equal(visited, tc.groups) {
				t.Fatalf("exits=%v selectors=%v err=%v", got, visited, err)
			}
		})
	}
}
