package routing

import "testing"

// TestDecide exercises suffix specificity, group priority, and exit selection,
// including blocking a matched group when its exits are unavailable.
func TestDecide(t *testing.T) {
	groups := []Group{
		{ID: "RU", Exits: []string{"RU-1"}},
		{ID: "FI", Exits: []string{"FI-1", "FI-2"}},
	}
	lists := []List{
		{ID: "fi", Group: "FI", Masks: []string{"*.deepseek.com", "*.tie.test"}},
		{ID: "off", Masks: []string{"*.disabled.com"}},
		{ID: "ru", Group: "RU", Masks: []string{"*.com", "*.tie.test"}},
	}
	fi := Decision{Group: "FI", Exit: "FI-1", List: "fi", Mask: "*.deepseek.com", Reason: Matched, Outcome: Forward}
	com := Decision{Group: "RU", Exit: "RU-1", List: "ru", Mask: "*.com", Reason: Matched, Outcome: Forward}
	tie := com
	tie.Mask = "*.tie.test"
	fallback := Decision{Group: "RU", Exit: "RU-1", Reason: Default, Outcome: Forward}
	reserve := fi
	reserve.Exit = "FI-2"
	blocked := fi
	blocked.Exit = ""
	blocked.Outcome = Block
	for _, tc := range []struct {
		name, domain string
		fi1, fi2     bool
		want         Decision
	}{
		{name: "apex", domain: "deepseek.com", fi1: true, fi2: true, want: fi},
		{name: "recursive", domain: "V1.API.DeepSeek.Com.", fi1: true, fi2: true, want: fi},
		{name: "labels", domain: "notdeepseek.com", fi1: true, fi2: true, want: com},
		{name: "tie", domain: "host.tie.test", fi1: true, fi2: true, want: tie},
		{name: "disabled", domain: "disabled.com", fi1: true, fi2: true, want: com},
		{name: "fallback", domain: "example.org", fi1: true, fi2: true, want: fallback},
		{name: "unnamed", domain: "", fi1: true, fi2: true, want: fallback},
		{name: "failover", domain: "deepseek.com", fi1: false, fi2: true, want: reserve},
		{name: "outage", domain: "deepseek.com", fi1: false, fi2: false, want: blocked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decide(groups, lists, map[string]bool{"RU-1": true, "FI-1": tc.fi1, "FI-2": tc.fi2}, tc.domain)
			if got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestInvalidInputsNeverForward verifies that malformed names and invalid active
// rules produce a rejection even when the default group has a healthy exit.
func TestInvalidInputsNeverForward(t *testing.T) {
	groups := []Group{
		{ID: "RU", Exits: []string{"RU-1"}},
		{ID: "FI", Exits: []string{"FI-1"}},
	}
	healthy := map[string]bool{"RU-1": true, "FI-1": true}
	for _, tc := range []struct {
		name, group, mask, domain string
		want                      Decision
	}{
		{name: "unknown group", group: "unknown", mask: "*.fi.test", domain: "x.fi.test", want: Decision{Reason: Invalid, Outcome: Reject}},
		{name: "trailing whitespace", group: "FI", mask: "*.fi.test ", domain: "x.fi.test", want: Decision{Reason: Invalid, Outcome: Reject}},
		{name: "bare mask", group: "FI", mask: "fi.test", domain: "fi.test", want: Decision{Reason: Invalid, Outcome: Reject}},
		{name: "malformed lookup", group: "FI", mask: "*.fi.test", domain: "x.fi.test..", want: Decision{Reason: InvalidName, Outcome: RejectName}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(groups, []List{{ID: "rule", Group: tc.group, Masks: []string{tc.mask}}}, healthy, tc.domain)
			if d != tc.want {
				t.Fatalf("unexpected route: %+v", d)
			}
		})
	}
}
