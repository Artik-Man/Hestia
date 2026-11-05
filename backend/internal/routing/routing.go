// Package routing decides the desired exit for one new flow without performing I/O.
package routing

import "strings"

// Groups and their exits are ordered by descending priority. The first group is the default.
type Group struct {
	ID    string
	Name  string `json:"name,omitempty"`
	Exits []string
}

// List identifies a set of domain masks with an optional display name and group binding.
type List struct {
	Name      string `json:"name,omitempty"`
	ID, Group string
	Masks     []string
}

type MatchReason string

const (
	Matched     MatchReason = "domain_rule"
	Default     MatchReason = "default_group"
	Invalid     MatchReason = "invalid_configuration"
	InvalidName MatchReason = "invalid_domain"
)

type Outcome string

const (
	Forward    Outcome = "forward"
	Block      Outcome = "block_no_available_exit"
	Reject     Outcome = "block_invalid_configuration"
	RejectName Outcome = "block_invalid_domain"
)

type Decision struct {
	Group, Exit, List, Mask string
	Reason                  MatchReason
	Outcome                 Outcome
}

// canonical converts a name to lower case and removes one terminal DNS root dot
// so absolute and relative spellings compare equally.
func canonical(s string) string { return strings.ToLower(strings.TrimSuffix(s, ".")) }

// validName accepts ASCII DNS hostnames, including already encoded IDNA labels.
func validName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidMask accepts an ASCII wildcard DNS suffix with an optional terminal root dot.
func ValidMask(mask string) bool {
	suffix, ok := strings.CutPrefix(mask, "*.")
	return ok && validName(strings.TrimSuffix(suffix, "."))
}

// groupRanks indexes groups by priority and returns nil for an empty topology,
// a missing ID, or a repeated group or exit ID.
func groupRanks(groups []Group) map[string]int {
	if len(groups) == 0 {
		return nil
	}
	rank := make(map[string]int, len(groups))
	exits := make(map[string]bool)
	for i, g := range groups {
		if _, dup := rank[g.ID]; g.ID == "" || dup {
			return nil
		}
		rank[g.ID] = i
		for _, exit := range g.Exits {
			if exit == "" || exits[exit] {
				return nil
			}
			exits[exit] = true
		}
	}
	return rank
}

// Decide evaluates one configuration and availability snapshot. Missing health means unavailable.
// The empty domain represents a flow to an IP with no known name. Other inputs must be ASCII DNS hostnames.
// Active lists accept only *.suffix masks, which include the suffix itself. Exit IDs are globally unique.
func Decide(groups []Group, lists []List, healthy map[string]bool, domain string) Decision {
	invalid := Decision{Reason: Invalid, Outcome: Reject}
	rank := groupRanks(groups)
	if rank == nil {
		return invalid
	}
	if domain != "" && !validName(strings.TrimSuffix(domain, ".")) {
		return Decision{Reason: InvalidName, Outcome: RejectName}
	}
	domain = canonical(domain)
	selected, best := 0, 0
	d := Decision{Reason: Default, Outcome: Block}
	for _, list := range lists {
		if list.Group == "" {
			continue
		}
		group, ok := rank[list.Group]
		if !ok {
			return invalid
		}
		for _, mask := range list.Masks {
			if !ValidMask(mask) {
				return invalid
			}
			suffix := canonical(mask[2:])
			if domain != suffix && !strings.HasSuffix(domain, "."+suffix) {
				continue
			}
			score := 1 + strings.Count(suffix, ".")
			if score > best || score == best && group < selected {
				best, selected = score, group
				d.List, d.Mask, d.Reason = list.ID, mask, Matched
			}
		}
	}
	g := groups[selected]
	d.Group = g.ID
	d.Exit, d.Outcome = SelectExit(g, healthy)
	return d
}

// SelectExit returns the first available exit of an already selected group.
func SelectExit(g Group, healthy map[string]bool) (string, Outcome) {
	for _, exit := range g.Exits {
		if healthy[exit] {
			return exit, Forward
		}
	}
	return "", Block
}
