package trafficcapture

import (
	"slices"
	"time"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

// TraceStageResult describes one packet, sing-box, or configuration-expectation stage in stdout output.
type TraceStageResult struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Count        int    `json:"count,omitempty"`
	ReverseCount int    `json:"reverseCount,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// TraceRouteState contains sanitized route snapshot booleans without exposing route dumps.
type TraceRouteState struct {
	Table               uint32
	LookupRule          bool
	GuardRule           bool
	RulesBeforeMain     bool
	TunnelDefault       bool
	UnreachableFallback bool
}

// TraceConfigurationExpectation contains only one non-secret policy identity and its route expectation stages.
type TraceConfigurationExpectation struct {
	PolicyKey      string
	ObservedAt     time.Time
	ConfiguredMark uint32
	NDMTable       uint32
	HestiaTable    uint32
	Stages         []TraceStageResult
}

// buildTraceConfigurationExpectation turns RCI/netlink snapshots into fixed, non-secret expectation stages.
func buildTraceConfigurationExpectation(assignment keeneticrci.ClientPolicyAssignment, assignmentErr error, policies []keeneticrci.IPPolicy, policyErr error, routes *TraceRouteState, routeErr error) TraceConfigurationExpectation {
	result := TraceConfigurationExpectation{Stages: make([]TraceStageResult, 0, 5)}
	if assignmentErr != nil {
		result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "unavailable", Detail: "read-only client-to-policy assignment snapshot failed"})
		return appendUnavailableRouteExpectations(result)
	}
	if !assignment.Found {
		result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "unavailable", Detail: "source address did not resolve to one active Keenetic client"})
		return appendUnavailableRouteExpectations(result)
	}
	if !assignment.Explicit || assignment.PolicyKey == "" {
		result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "unavailable", Detail: "client has no resolved explicit IP policy assignment"})
		return appendUnavailableRouteExpectations(result)
	}
	if policyErr != nil {
		result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "unavailable", Detail: "read-only RCI policy snapshot failed"})
		return appendUnavailableRouteExpectations(result)
	}
	var selected *keeneticrci.IPPolicy
	for i := range policies {
		if policies[i].Key == assignment.PolicyKey {
			selected = &policies[i]
			break
		}
	}
	if selected == nil {
		result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "unavailable", Detail: "assigned policy is absent from the current RCI policy inventory"})
		return appendUnavailableRouteExpectations(result)
	}
	result.ConfiguredMark, result.NDMTable = selected.Mark4, selected.Table4
	result.HestiaTable = traceTableForMark(selected.Mark4)
	result.PolicyKey = assignment.PolicyKey
	result.Stages = append(result.Stages, TraceStageResult{Name: "ndm_policy", Status: "configured_expectation", Detail: "source maps to explicit policy " + assignment.PolicyKey + "; OpkgTun0 permitted=" + traceBoolText(slices.Contains(selected.OpkgTunInterfaces, "OpkgTun0")) + "; packet classification is unverified"})
	if routeErr != nil || routes == nil {
		return appendUnavailableRouteExpectations(result)
	}
	result.HestiaTable = routes.Table
	result.Stages = append(result.Stages,
		TraceStageResult{Name: "hestia_lookup_rule", Status: "configured_expectation", Detail: "exact priority-7 mark+iif br0 lookup present=" + traceBoolText(routes.LookupRule)},
		TraceStageResult{Name: "hestia_guard_rule", Status: "configured_expectation", Detail: "exact priority-8 unreachable guard present=" + traceBoolText(routes.GuardRule)},
		TraceStageResult{Name: "hestia_rule_order", Status: "configured_expectation", Detail: "both Hestia rules precede main lookup=" + traceBoolText(routes.RulesBeforeMain)},
		TraceStageResult{Name: "hestia_table_routes", Status: "configured_expectation", Detail: "default dev opkgtun0=" + traceBoolText(routes.TunnelDefault) + "; unreachable fallback=" + traceBoolText(routes.UnreachableFallback)})
	return result
}

// traceTableForMark mirrors the stable Hestia mark-to-table mapping for the configured expectation summary.
func traceTableForMark(mark uint32) uint32 {
	if mark < 0x0ffff000 || mark > 0x0fffffff {
		return 0
	}
	return 30000 + mark - 0x0ffff000
}

// appendUnavailableRouteExpectations identifies route snapshots that could not be read or associated with a selected policy.
func appendUnavailableRouteExpectations(result TraceConfigurationExpectation) TraceConfigurationExpectation {
	for _, item := range []struct{ name, detail string }{{"hestia_lookup_rule", "route identity unavailable"}, {"hestia_guard_rule", "route identity unavailable"}, {"hestia_rule_order", "route identity unavailable"}, {"hestia_table_routes", "route identity unavailable"}} {
		result.Stages = append(result.Stages, TraceStageResult{Name: item.name, Status: "unavailable", Detail: item.detail})
	}
	return result
}

// traceBoolText formats one boolean without retaining raw config or route output.
func traceBoolText(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
