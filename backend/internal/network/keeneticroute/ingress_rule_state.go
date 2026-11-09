//go:build keenetic

package keeneticroute

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
)

const (
	ingressRuleStateVersion = 1
	maxIngressRuleStateSize = 64 * 1024
	maxIngressOwnedRules    = 256
)

type ingressRuleRegistry struct {
	Version int           `json:"version"`
	Rules   []ingressRule `json:"rules"`
}

// parseIngressRuleRegistry validates a canonical bounded ownership record and rejects duplicate or malformed rule identities.
func parseIngressRuleRegistry(data []byte) ([]ingressRule, error) {
	if len(data) == 0 || len(data) > maxIngressRuleStateSize || data[len(data)-1] != '\n' {
		return nil, errors.New("invalid ingress rule ownership record size or terminator")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var registry ingressRuleRegistry
	if err := decoder.Decode(&registry); err != nil {
		return nil, errors.New("invalid ingress rule ownership record")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("ingress rule ownership record has trailing data")
	}
	if registry.Version != ingressRuleStateVersion || len(registry.Rules) > maxIngressOwnedRules {
		return nil, errors.New("unsupported ingress rule ownership record")
	}
	seen := make(map[ingressRule]struct{}, len(registry.Rules))
	for index := range registry.Rules {
		rule := registry.Rules[index]
		if !validIngressRuleIdentity(rule) {
			return nil, errors.New("invalid ingress rule identity in ownership record")
		}
		rule.Owned = false
		if _, exists := seen[rule]; exists {
			return nil, errors.New("duplicate ingress rule identity in ownership record")
		}
		seen[rule] = struct{}{}
		registry.Rules[index] = rule
	}
	canonical, err := encodeIngressRuleRegistry(registry.Rules)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errors.New("ingress rule ownership record is not canonical")
	}
	return registry.Rules, nil
}

// encodeIngressRuleRegistry emits a stable newline-terminated ownership record with no runtime-only ownership flags.
func encodeIngressRuleRegistry(rules []ingressRule) ([]byte, error) {
	if len(rules) > maxIngressOwnedRules {
		return nil, errors.New("too many Hestia-owned policy rules")
	}
	canonical := append([]ingressRule(nil), rules...)
	for index := range canonical {
		canonical[index].Owned = false
		if !validIngressRuleIdentity(canonical[index]) {
			return nil, errors.New("invalid Hestia-owned policy rule identity")
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		a, b := canonical[left], canonical[right]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Mark != b.Mark {
			return a.Mark < b.Mark
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Input != b.Input {
			return a.Input < b.Input
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Mask < b.Mask
	})
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, errors.New("duplicate Hestia-owned policy rule identity")
		}
	}
	encoded, err := json.Marshal(ingressRuleRegistry{Version: ingressRuleStateVersion, Rules: canonical})
	if err != nil {
		return nil, errors.New("cannot encode ingress rule ownership record")
	}
	return append(encoded, '\n'), nil
}

// validIngressRuleIdentity accepts only normalized Hestia selectors that can be stored as owned policy rules.
func validIngressRuleIdentity(rule ingressRule) bool {
	if (rule.Family != ingressIPv4Family && rule.Family != ingressIPv6Family) ||
		(rule.Priority != ingressRoutePriority && rule.Priority != ingressBlockPriority) ||
		rule.Protocol != 0 || rule.Mark < 0x0ffff000 || rule.Mark > 0x0fffffff ||
		rule.Mask != 0xffffffff || rule.Table > ingressTableMaximum || rule.Action == 0 ||
		!rule.HasMark || rule.Input == "" || !ingressInterfacePattern.MatchString(rule.Input) ||
		rule.SourcePrefixBits != 0 || rule.DestPrefixBits != 0 || rule.TOS != 0 || rule.Flags != 0 ||
		rule.HasOtherSelectors || rule.Owned {
		return false
	}
	if rule.Action == ingressRuleLookup {
		return rule.Family == ingressIPv4Family && rule.Table >= ingressTableMinimum
	}
	return rule.Action == ingressRuleUnreachable && rule.Table == 0
}
