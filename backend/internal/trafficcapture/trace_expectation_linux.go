//go:build linux && arm64 && !android && keenetic

package trafficcapture

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Artik-Man/Hestia/internal/network/keeneticroute"
	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

// ReadTraceConfigurationForCommand resolves the source client and reads fixed loopback RCI and route-netlink expectations without changing router state.
func ReadTraceConfigurationForCommand(ctx context.Context, source string) TraceConfigurationExpectation {
	observedAt := time.Now().UTC()
	finish := func(result TraceConfigurationExpectation) TraceConfigurationExpectation {
		result.ObservedAt = observedAt
		return result
	}
	client, err := keeneticrci.NewClient(keeneticrci.Config{BaseURL: "http://127.0.0.1:79", TokenSource: keeneticrci.FileTokenSource{Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token")}, Timeout: 3 * time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		return finish(buildTraceConfigurationExpectation(keeneticrci.ClientPolicyAssignment{}, err, nil, nil, nil, err))
	}
	assignment, assignmentErr := client.ReadClientPolicyAssignment(ctx, source)
	if assignmentErr != nil || !assignment.Found || !assignment.Explicit {
		return finish(buildTraceConfigurationExpectation(assignment, assignmentErr, nil, nil, nil, nil))
	}
	policies, err := client.ReadIPPolicies(ctx)
	if err != nil {
		return finish(buildTraceConfigurationExpectation(assignment, nil, nil, err, nil, err))
	}
	var selected *keeneticrci.IPPolicy
	for i := range policies {
		if policies[i].Key == assignment.PolicyKey {
			selected = &policies[i]
			break
		}
	}
	if selected == nil {
		return finish(buildTraceConfigurationExpectation(assignment, nil, policies, nil, nil, nil))
	}
	route, routeErr := keeneticroute.ReadIngressExpectation(ctx, storage.Installed().IngressRuleState, selected.Mark4, "br0", "opkgtun0")
	state := TraceRouteState{Table: route.Table, LookupRule: route.LookupRule, GuardRule: route.GuardRule, RulesBeforeMain: route.RulesBeforeMain, TunnelDefault: route.TunnelDefault, UnreachableFallback: route.UnreachableFallback}
	return finish(buildTraceConfigurationExpectation(assignment, nil, policies, nil, &state, routeErr))
}
