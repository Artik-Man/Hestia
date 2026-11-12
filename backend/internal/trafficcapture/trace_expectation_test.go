package trafficcapture

import (
	"errors"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

// TestTraceConfigurationExpectationsHandlesPolicyAndRouteFailures checks missing, denied, mismatched, and unavailable snapshots.
func TestTraceConfigurationExpectationsHandlesPolicyAndRouteFailures(t *testing.T) {
	policy := keeneticrci.IPPolicy{Key: "Policy2", Table4: 4102, Mark4: 0x0ffffaac}
	assignment := keeneticrci.ClientPolicyAssignment{PolicyKey: "Policy2", Found: true, Explicit: true}
	missing := buildTraceConfigurationExpectation(keeneticrci.ClientPolicyAssignment{}, nil, []keeneticrci.IPPolicy{policy}, nil, nil, nil)
	if missing.Stages[0].Status != "unavailable" || missing.ConfiguredMark != 0 {
		t.Fatalf("missing policy stage: %+v", missing)
	}

	denied := buildTraceConfigurationExpectation(assignment, nil, []keeneticrci.IPPolicy{policy}, nil, nil, errors.New("route snapshot unavailable"))
	if denied.Stages[0].Status != "configured_expectation" || denied.PolicyKey != "Policy2" || denied.ConfiguredMark != policy.Mark4 || denied.NDMTable != policy.Table4 || !strings.Contains(denied.Stages[0].Detail, "permitted=no") || denied.Stages[1].Status != "unavailable" {
		t.Fatalf("non-permitting policy stage: %+v", denied)
	}
	policy.OpkgTunInterfaces = []string{"OpkgTun0"}
	routeState := &TraceRouteState{Table: 32732, LookupRule: false, GuardRule: true, RulesBeforeMain: false, TunnelDefault: true, UnreachableFallback: false}
	mismatch := buildTraceConfigurationExpectation(assignment, nil, []keeneticrci.IPPolicy{policy}, nil, routeState, nil)
	if mismatch.Stages[0].Status != "configured_expectation" || !strings.Contains(mismatch.Stages[0].Detail, "source maps to explicit policy Policy2") || !strings.Contains(mismatch.Stages[1].Detail, "present=no") || !strings.Contains(mismatch.Stages[2].Detail, "present=yes") || !strings.Contains(mismatch.Stages[3].Detail, "precede main lookup=no") || !strings.Contains(mismatch.Stages[4].Detail, "unreachable fallback=no") {
		t.Fatalf("mismatched route stages: %+v", mismatch)
	}
	failed := buildTraceConfigurationExpectation(assignment, nil, nil, errors.New("RCI failed"), nil, errors.New("netlink failed"))
	for _, stage := range failed.Stages {
		if stage.Status != "unavailable" {
			t.Fatalf("failed snapshot asserted configuration: %+v", failed)
		}
	}
}

// TestTraceConfigurationExpectationsRejectsUnresolvedClientAssignment prevents a policy hint from becoming client assignment evidence.
func TestTraceConfigurationExpectationsRejectsUnresolvedClientAssignment(t *testing.T) {
	policy := keeneticrci.IPPolicy{Key: "Policy2", Table4: 4102, Mark4: 0x0ffffaac}
	for _, assignment := range []keeneticrci.ClientPolicyAssignment{{}, {Found: true}, {Found: true, Explicit: false}} {
		result := buildTraceConfigurationExpectation(assignment, nil, []keeneticrci.IPPolicy{policy}, nil, nil, nil)
		if result.PolicyKey != "" || result.Stages[0].Status != "unavailable" {
			t.Fatalf("unresolved assignment asserted a policy: %+v", result)
		}
		for _, stage := range result.Stages[1:] {
			if stage.Status != "unavailable" {
				t.Fatalf("dependent snapshot stage should be unavailable: %+v", result)
			}
		}
	}
}
