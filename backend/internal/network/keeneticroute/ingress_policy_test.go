//go:build keenetic

package keeneticroute

import (
	"context"
	"errors"
	"testing"
)

// memoryIngressOps models route-netlink state so ingress lifecycle ordering is testable without a router.
type memoryIngressOps struct {
	routes   []ingressRoute
	rules    []ingressRule
	links    map[string]bool
	steps    []string
	addErr   error
	ruleErrs map[ingressRule]error
	routeErr error
}

// Routes returns a copy of routes owned by the requested table.
func (ops *memoryIngressOps) Routes(_ context.Context, table uint32) ([]ingressRoute, error) {
	if ops.routeErr != nil {
		return nil, ops.routeErr
	}
	var result []ingressRoute
	for _, route := range ops.routes {
		if table == 0 || route.Table == table {
			result = append(result, route)
		}
	}
	return result, nil
}

// Rules returns a copy of the simulated RPDB state.
func (ops *memoryIngressOps) Rules(context.Context) ([]ingressRule, error) {
	return append([]ingressRule(nil), ops.rules...), nil
}

// LinkUp reports whether the requested simulated interface is available.
func (ops *memoryIngressOps) LinkUp(_ context.Context, name string) (bool, error) {
	return ops.links[name], nil
}

// AddRoute records a simulated route addition unless the test configured an error.
func (ops *memoryIngressOps) AddRoute(_ context.Context, route ingressRoute) error {
	ops.steps = append(ops.steps, "add-route")
	if ops.addErr != nil {
		return ops.addErr
	}
	ops.routes = append(ops.routes, route)
	return nil
}

// DeleteRoute removes one exact simulated route.
func (ops *memoryIngressOps) DeleteRoute(_ context.Context, route ingressRoute) error {
	ops.steps = append(ops.steps, "delete-route")
	for index, current := range ops.routes {
		if current == route {
			ops.routes = append(ops.routes[:index], ops.routes[index+1:]...)
			return nil
		}
	}
	return errors.New("route not found")
}

// AddRule records a simulated policy rule addition.
func (ops *memoryIngressOps) AddRule(_ context.Context, rule ingressRule) error {
	ops.steps = append(ops.steps, "add-rule")
	if err := ops.ruleErrs[rule]; err != nil {
		return err
	}
	rule.Owned = true
	ops.rules = append(ops.rules, rule)
	return nil
}

// TestIngressPolicyFallsBackToUnreachableTable keeps IPv4 blocked if the first RPDB terminal rule cannot install.
func TestIngressPolicyFallsBackToUnreachableTable(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{
		links: map[string]bool{"br0": true},
		ruleErrs: map[ingressRule]error{
			{Family: ingressIPv4Family, Priority: ingressBlockPriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Action: ingressRuleUnreachable, Input: "br0", HasMark: true}: errors.New("temporary terminal rule failure"),
		},
	}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.InstallGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if !containsExactRoute(ops.routes, policy.guardRoute(ingressGuardFloorMetric)) ||
		!containsExactRule(ops.rules, policy.lookupRule) || !containsExactRule(ops.rules, policy.ipv6Rule) ||
		containsExactRule(ops.rules, policy.blockRule) {
		t.Fatalf("fallback table guard was not installed after terminal-rule failure: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
	if len(ops.steps) < 4 || ops.steps[0] != "add-rule" || ops.steps[1] != "add-route" ||
		ops.steps[2] != "add-rule" || ops.steps[3] != "add-rule" {
		t.Fatalf("fallback rules were not published before IPv4 lookup: %#v", ops.steps)
	}
}

// TestIngressPolicyKeepsIPv4GuardWhenIPv6RuleFails proves IPv6 setup failure cannot skip the IPv4 lookup fallback.
func TestIngressPolicyKeepsIPv4GuardWhenIPv6RuleFails(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	ops.ruleErrs = map[ingressRule]error{
		policy.blockRule: errors.New("terminal rule failure"),
		policy.ipv6Rule:  errors.New("IPv6 rule failure"),
	}
	if err := policy.InstallGuard(ctx); err == nil {
		t.Fatal("IPv6 rule failure must be reported to the supervisor")
	}
	if !containsExactRoute(ops.routes, policy.guardRoute(ingressGuardFloorMetric)) ||
		!containsExactRule(ops.rules, policy.lookupRule) {
		t.Fatalf("IPv6 failure prevented the IPv4 fallback guard: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
	if len(ops.steps) < 4 || ops.steps[0] != "add-rule" || ops.steps[1] != "add-route" ||
		ops.steps[2] != "add-rule" || ops.steps[3] != "add-rule" {
		t.Fatalf("IPv4 lookup was not attempted after the failed IPv6 rule: %#v", ops.steps)
	}
}

// containsExactRoute reports whether a modeled route exists in the simulated netlink dump.
func containsExactRoute(routes []ingressRoute, wanted ingressRoute) bool {
	for _, route := range routes {
		if route == wanted {
			return true
		}
	}
	return false
}

// containsExactRule reports whether a modeled rule exists in the simulated netlink dump.
func containsExactRule(rules []ingressRule, wanted ingressRule) bool {
	for _, rule := range rules {
		if sameIngressRuleIdentity(rule, wanted) {
			return true
		}
	}
	return false
}

// DeleteRule removes one exact simulated policy rule.
func (ops *memoryIngressOps) DeleteRule(_ context.Context, rule ingressRule) error {
	ops.steps = append(ops.steps, "delete-rule")
	for index, current := range ops.rules {
		if sameIngressRuleIdentity(current, rule) {
			ops.rules = append(ops.rules[:index], ops.rules[index+1:]...)
			return nil
		}
	}
	return errors.New("rule not found")
}

// TestIngressPolicyLifecycleKeepsGuardUntilTunnelReady verifies blocked startup and guarded activation ordering.
func TestIngressPolicyLifecycleKeepsGuardUntilTunnelReady(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.InstallGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 1 || ops.routes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("startup must have only the floor guard route: %#v", ops.routes)
	}
	if len(ops.rules) != 3 || !sameIngressRuleIdentity(ops.rules[0], policy.blockRule) || !sameIngressRuleIdentity(ops.rules[1], policy.ipv6Rule) || !sameIngressRuleIdentity(ops.rules[2], policy.lookupRule) {
		t.Fatalf("startup rules do not install the IPv4 fallback before the lookup rule: %#v", ops.rules)
	}
	if len(ops.steps) < 4 || ops.steps[0] != "add-rule" || ops.steps[1] != "add-rule" ||
		ops.steps[2] != "add-route" || ops.steps[3] != "add-rule" {
		t.Fatalf("IPv4 fail-closed rule was not installed before the lookup path: %#v", ops.steps)
	}
	ops.links["opkgtun0"] = true
	ops.steps = nil
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 2 || ops.routes[0] != policy.tunnelRoute() || ops.routes[1] != policy.guardRoute(ingressGuardMetric) {
		t.Fatalf("active table must have TUN default and high-metric guard: %#v", ops.routes)
	}
	if got := ops.steps[len(ops.steps)-1]; got != "delete-route" {
		t.Fatalf("activation must remove floor guard last, got %q in %#v", got, ops.steps)
	}
	ops.steps = nil
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	for _, step := range ops.steps {
		if step == "add-route" {
			t.Fatalf("steady-state reconciliation must not reinstall the blocking floor guard: %#v", ops.steps)
		}
	}
	if err := policy.DeactivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 1 || ops.routes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("deactivation must leave only the blocking route: %#v", ops.routes)
	}
}

// TestIngressPolicyRepairsMissingFallback restores the high-metric guard before retaining an active TUN route.
func TestIngressPolicyRepairsMissingFallback(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true, "opkgtun0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ops.DeleteRoute(ctx, policy.guardRoute(ingressGuardMetric)); err != nil {
		t.Fatal(err)
	}
	ops.steps = nil
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	fallbackPresent := false
	for _, route := range ops.routes {
		if route == policy.guardRoute(ingressGuardMetric) {
			fallbackPresent = true
		}
	}
	if !fallbackPresent {
		t.Fatalf("steady-state activation did not restore fallback guard: %#v", ops.routes)
	}
	if len(ops.steps) == 0 || ops.steps[0] != "add-route" {
		t.Fatalf("fallback guard was not restored before rule repair: %#v", ops.steps)
	}
}

// TestIngressPolicyRemoveRestoresThePreFeatureState checks explicit teardown removes every owned route and rule.
func TestIngressPolicyRemoveRestoresThePreFeatureState(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true, "opkgtun0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatal(err)
	}
	if err := policy.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 0 || len(ops.rules) != 0 {
		t.Fatalf("teardown left owned routing state: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
}

// TestIngressPolicyRemoveRejectsForeignStateBeforeMutation protects routes and rules owned by Keenetic or another service.
func TestIngressPolicyRemoveRejectsForeignStateBeforeMutation(t *testing.T) {
	ops := &memoryIngressOps{
		links:  map[string]bool{"br0": true},
		routes: []ingressRoute{{Table: 30001, PrefixBits: 24, Type: ingressUnicast, Device: "br0"}},
	}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Remove(context.Background()); err == nil {
		t.Fatal("teardown accepted an unowned route")
	}
	if len(ops.routes) != 1 || len(ops.rules) != 0 {
		t.Fatalf("teardown mutated state after ownership failure: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
}

// TestIngressPolicyOwnershipIncludesProtocolOrigin prevents adopting a rule with foreign kernel provenance.
func TestIngressPolicyOwnershipIncludesProtocolOrigin(t *testing.T) {
	policy, err := NewIngressPolicy(&memoryIngressOps{}, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	owned := policy.lookupRule
	owned.Owned = true
	if !policy.isOwnedRule(owned) {
		t.Fatalf("canonical Hestia rule was not recognized: %+v", owned)
	}
	foreign := owned
	foreign.Protocol = 2
	if policy.isOwnedRule(foreign) {
		t.Fatalf("rule with foreign protocol provenance was adopted: %+v", foreign)
	}
}

// TestIngressPolicyRejectsExactUnownedRule prevents adoption of a foreign rule with identical selectors but no persisted owner record.
func TestIngressPolicyRejectsExactUnownedRule(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	ops.rules = append(ops.rules, policy.lookupRule)
	if err := policy.Preflight(ctx); err == nil {
		t.Fatal("preflight adopted an exact rule without a persisted ownership record")
	}
	if len(ops.routes) != 0 || len(ops.rules) != 1 {
		t.Fatalf("preflight mutated state after finding an unowned exact rule: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
}

// TestIngressPolicyPreflightRejectsOverlappingSelectorsAndForeignRoutes protects NDM and AWG state.
func TestIngressPolicyPreflightRejectsOverlappingSelectorsAndForeignRoutes(t *testing.T) {
	ctx := context.Background()
	for name, configure := range map[string]func(*memoryIngressOps, IngressPolicy){
		"overlapping selector": func(ops *memoryIngressOps, policy IngressPolicy) {
			ops.rules = append(ops.rules, ingressRule{Family: 2, Priority: ingressRoutePriority, Table: 202, Action: ingressRuleLookup})
		},
		"foreign table route": func(ops *memoryIngressOps, policy IngressPolicy) {
			ops.routes = append(ops.routes, ingressRoute{Table: 30001, PrefixBits: 24, Type: ingressUnicast, Device: "br0"})
		},
		"same mark selector": func(ops *memoryIngressOps, policy IngressPolicy) {
			ops.rules = append(ops.rules, ingressRule{Family: 2, Priority: ingressRoutePriority, Mark: policy.mark, Mask: 0xffffffff, HasMark: true})
		},
		"overlapping IPv6 selector": func(ops *memoryIngressOps, policy IngressPolicy) {
			ops.rules = append(ops.rules, ingressRule{Family: ingressIPv6Family, Priority: ingressRoutePriority, Mark: policy.mark, Mask: 0xffffffff, HasMark: true})
		},
		"foreign table owner": func(ops *memoryIngressOps, policy IngressPolicy) {
			ops.rules = append(ops.rules, ingressRule{Family: 2, Priority: 500, Table: policy.table, Action: ingressRuleLookup})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
			policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
			if err != nil {
				t.Fatal(err)
			}
			configure(ops, policy)
			if err := policy.Preflight(ctx); err == nil {
				t.Fatal("expected preflight rejection")
			}
		})
	}
}

// TestIngressPolicyActivationFailureRetainsFloorGuard verifies a missing TUN cannot open a bypass route.
func TestIngressPolicyActivationFailureRetainsFloorGuard(t *testing.T) {
	ctx := context.Background()
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	err = policy.ActivateIPv4(ctx)
	if err == nil {
		t.Fatal("expected TUN readiness failure")
	}
	if len(ops.routes) != 1 || ops.routes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("failed activation must retain floor guard: %#v", ops.routes)
	}
}

// TestNewIngressPolicyRejectsInvalidInterfaceNames keeps netlink selectors within Linux interface-name limits.
func TestNewIngressPolicyRejectsInvalidInterfaceNames(t *testing.T) {
	for _, ingress := range []string{"", "bridge-interface-name-too-long", "br0\x00spoof", "br/0"} {
		if _, err := NewIngressPolicy(&memoryIngressOps{}, 30001, 0x0ffffabc, ingress, "opkgtun0"); err == nil {
			t.Errorf("invalid ingress interface %q was accepted", ingress)
		}
	}
}

// TestIngressTableForMarkMapsTheCompleteKeeneticPolicyRangeWithoutCollisions checks deterministic table assignment.
func TestIngressTableForMarkMapsTheCompleteKeeneticPolicyRangeWithoutCollisions(t *testing.T) {
	first, err := IngressTableForMark(0x0ffff000)
	if err != nil || first != ingressTableMinimum {
		t.Fatalf("first supported mark mapped to %d, %v", first, err)
	}
	last, err := IngressTableForMark(0x0fffffff)
	if err != nil || last != ingressTableMaximum {
		t.Fatalf("last supported mark mapped to %d, %v", last, err)
	}
	for _, mark := range []uint32{0, 0x0fffefff, 0x10000000} {
		if _, err := IngressTableForMark(mark); err == nil {
			t.Errorf("out-of-range mark %#x was accepted", mark)
		}
	}
}

// TestIngressPolicyTeardownRejectsUnknownRouteState prevents a failed inventory from being treated as absence.
func TestIngressPolicyTeardownRejectsUnknownRouteState(t *testing.T) {
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}, routeErr: errors.New("inventory failed")}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.deleteIfPresent(context.Background(), policy.tunnelRoute()); err == nil {
		t.Fatal("expected failure when route inventory is unknown")
	}
}
