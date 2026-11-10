//go:build linux && keenetic

package keeneticroute

import "testing"

// TestBuildIngressExpectationRequiresExactRulesAndRoutes distinguishes missing or mismatched configuration objects.
func TestBuildIngressExpectationRequiresExactRulesAndRoutes(t *testing.T) {
	mark := uint32(0x0ffffaac)
	table, err := IngressTableForMark(mark)
	if err != nil {
		t.Fatal(err)
	}
	policy := IngressPolicy{table: table, mark: mark, ingress: "br0", tunnel: "opkgtun0", lookupRule: ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: mark, Mask: 0xffffffff, Table: table, Action: ingressRuleLookup, Input: "br0", HasMark: true}, blockRule: ingressRule{Family: ingressIPv4Family, Priority: ingressBlockPriority, Mark: mark, Mask: 0xffffffff, Table: table, Action: ingressRuleUnreachable, Input: "br0", HasMark: true}}
	rules := []ingressRule{
		policy.lookupRule,
		policy.blockRule,
		{Family: ingressIPv4Family, Priority: 9, Table: 254, Action: ingressRuleLookup},
	}
	rules[0].Owned, rules[1].Owned = true, true
	routes := []ingressRoute{policy.tunnelRoute(), policy.guardRoute(ingressGuardMetric)}
	complete := buildIngressExpectation(policy, rules, routes)
	if !complete.LookupRule || !complete.GuardRule || !complete.RulesBeforeMain || !complete.TunnelDefault || !complete.UnreachableFallback {
		t.Fatalf("complete expected config not recognized: %+v", complete)
	}

	mutatedRule := rules[0]
	mutatedRule.Mark++
	mutated := buildIngressExpectation(policy, append([]ingressRule{mutatedRule}, rules[1:]...), routes)
	if mutated.LookupRule || !mutated.GuardRule {
		t.Fatalf("mismatched mark rule accepted: %+v", mutated)
	}
	lateMain := append([]ingressRule{rules[0], rules[1]}, ingressRule{Family: ingressIPv4Family, Priority: 7, Table: 254, Action: ingressRuleLookup})
	late := buildIngressExpectation(policy, lateMain, routes)
	if late.RulesBeforeMain {
		t.Fatalf("rules ordered at/after main were accepted: %+v", late)
	}
	mutatedRoutes := []ingressRoute{policy.tunnelRoute(), policy.guardRoute(ingressGuardMetric)}
	mutatedRoutes[0].Device = "eth3"
	mutatedRoutes[1].Metric++
	missing := buildIngressExpectation(policy, rules, mutatedRoutes)
	if missing.TunnelDefault || missing.UnreachableFallback {
		t.Fatalf("mismatched routes accepted: %+v", missing)
	}
}
