//go:build linux && keenetic

package keeneticroute

import (
	"context"
	"errors"
)

// IngressExpectation contains booleans from a read-only RPDB and FIB snapshot for one mark.
type IngressExpectation struct {
	Table               uint32
	LookupRule          bool
	GuardRule           bool
	RulesBeforeMain     bool
	TunnelDefault       bool
	UnreachableFallback bool
}

// ReadIngressExpectation reads exact Hestia rule and route identities without changing kernel state.
func ReadIngressExpectation(ctx context.Context, ownershipPath string, mark uint32, ingress, tunnel string) (IngressExpectation, error) {
	table, err := IngressTableForMark(mark)
	if err != nil {
		return IngressExpectation{}, err
	}
	policy, err := NewIngressPolicy(NetlinkIngressOps{OwnershipPath: ownershipPath}, table, mark, ingress, tunnel)
	if err != nil {
		return IngressExpectation{}, errors.New("cannot prepare read-only Hestia ingress snapshot")
	}
	rules, err := policy.ops.Rules(ctx)
	if err != nil {
		return IngressExpectation{}, err
	}
	routes, err := policy.ops.Routes(ctx, table)
	if err != nil {
		return IngressExpectation{}, err
	}
	return buildIngressExpectation(policy, rules, routes), nil
}

// buildIngressExpectation compares snapshots with the exact Hestia rule and route identities for one ingress policy.
func buildIngressExpectation(policy IngressPolicy, rules []ingressRule, routes []ingressRoute) IngressExpectation {
	result := IngressExpectation{Table: policy.table}
	for _, rule := range rules {
		if rule.Family == ingressIPv4Family && rule.Owned && sameIngressRuleIdentity(rule, policy.lookupRule) {
			result.LookupRule = true
		}
		if rule.Family == ingressIPv4Family && rule.Owned && sameIngressRuleIdentity(rule, policy.blockRule) {
			result.GuardRule = true
		}
	}
	mainPriority := uint32(^uint32(0))
	for _, rule := range rules {
		if rule.Family == ingressIPv4Family && rule.Table == 254 && rule.Action == ingressRuleLookup && !rule.HasMark && rule.Input == "" && !rule.HasOtherSelectors && rule.Priority < mainPriority {
			mainPriority = rule.Priority
		}
	}
	result.RulesBeforeMain = result.LookupRule && result.GuardRule && mainPriority != ^uint32(0) && ingressRoutePriority < ingressBlockPriority && ingressBlockPriority < mainPriority
	for _, route := range routes {
		if route == policy.tunnelRoute() {
			result.TunnelDefault = true
		}
		if route == policy.guardRoute(ingressGuardMetric) {
			result.UnreachableFallback = true
		}
	}
	return result
}
