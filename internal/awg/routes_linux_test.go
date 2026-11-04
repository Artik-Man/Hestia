package awg

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRouteRunner struct {
	outputs map[string]string
	fail    map[string]bool
	calls   []string
}

// Run records structured route commands and returns only configured fake command results.
func (f *fakeRouteRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	call := strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.fail[call] {
		return nil, errors.New("fake command failure")
	}
	return []byte(f.outputs[call]), nil
}

// TestRoutePolicyPreflightRejectsIPv4AndIPv6Collisions verifies both routing families are checked before mutations.
func TestRoutePolicyPreflightRejectsIPv4AndIPv6Collisions(t *testing.T) {
	for _, rules := range []string{
		"1002: from all lookup 202",
		"1200: from all fwmark 0x200/0xff8 lookup 201",
	} {
		runner := cleanRouteRunner()
		runner.outputs["-6 rule show"] = rules
		if err := NewRoutePolicy(runner).Preflight(context.Background()); err == nil {
			t.Fatalf("accepted colliding rule %q", rules)
		}
	}
	runner := cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "unreachable default metric 32767"
	if err := NewRoutePolicy(runner).Preflight(context.Background()); err == nil {
		t.Fatal("accepted occupied IPv4 policy table")
	}
}

// TestInstallGuardPlacesBothFamilyGuardsBeforeMarkRules checks IPv4 and IPv6 unreachable defaults are installed first.
func TestInstallGuardPlacesBothFamilyGuardsBeforeMarkRules(t *testing.T) {
	runner := cleanRouteRunner()
	policy := NewRoutePolicy(runner)
	if err := policy.InstallGuard(context.Background()); err != nil {
		t.Fatalf("InstallGuard returned error: %v", err)
	}
	if len(runner.calls) < 7 {
		t.Fatalf("too few preflight/install commands: %#v", runner.calls)
	}
	if got := runner.calls[len(runner.calls)-2:]; strings.Join(got, "|") != "-4 route add unreachable default table 202 metric 32767|-6 route add unreachable default table 202 metric 32767" {
		t.Fatalf("guard installation order: %#v", got)
	}
	if err := policy.InstallMarkRules(context.Background()); err == nil {
		t.Fatal("installed mark rules without visible IPv4 and IPv6 guards")
	}
}

// TestRoutePolicyIPv6NeverGetsAnAWGDefault verifies activation adds only the IPv4 tunnel route.
func TestRoutePolicyIPv6NeverGetsAnAWGDefault(t *testing.T) {
	runner := cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "default dev awg0 metric 100\nunreachable default metric 32767"
	runner.outputs["-6 route show table 202"] = "unreachable default metric 32767"
	runner.outputs["-4 rule show"] = "1002: from all fwmark 0x202/0xffffffff lookup 202"
	runner.outputs["-6 rule show"] = "1002: from all fwmark 0x202/0xffffffff lookup 202"
	runner.outputs["-o link show"] = "7: awg0: <POINTOPOINT,UP>"
	if err := NewRoutePolicy(runner).ActivateIPv4(context.Background()); err != nil {
		t.Fatalf("ActivateIPv4 returned error: %v", err)
	}
	if !strings.Contains(runner.calls[len(runner.calls)-1], "-4 route add default dev awg0") {
		t.Fatalf("IPv4 AWG route was not installed: %#v", runner.calls)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "-6 route add default dev awg0") {
			t.Fatalf("IPv6 route to AWG was installed: %q", call)
		}
	}
}

// TestRouteTeardownRequiresOutboundDrain leaves fail-closed routes intact if sing-box cannot confirm deactivation.
func TestRouteTeardownRequiresOutboundDrain(t *testing.T) {
	runner := cleanRouteRunner()
	policy := NewRoutePolicy(runner)
	if err := policy.Teardown(context.Background(), func(context.Context) error { return errors.New("not disabled") }); err == nil {
		t.Fatal("Teardown ignored the failed outbound drain")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Teardown changed routes before drain confirmation: %#v", runner.calls)
	}
}

// TestRouteTeardownDeletesOnlyExactOwnedRoutes verifies outbound drain precedes removal and unknown table entries remain untouched.
func TestRouteTeardownDeletesOnlyExactOwnedRoutes(t *testing.T) {
	runner := cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "default dev awg0 metric 100\nunreachable default metric 32767"
	runner.outputs["-6 route show table 202"] = "unreachable default metric 32767"
	runner.outputs["-4 rule show"] = "1002: from all fwmark 0x202/0xffffffff lookup 202"
	runner.outputs["-6 rule show"] = "1002: from all fwmark 0x202/0xffffffff lookup 202"
	policy := NewRoutePolicy(runner)
	if err := policy.Teardown(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Teardown failed for exact owned state: %v", err)
	}
	last := runner.calls[len(runner.calls)-5:]
	want := []string{
		"-4 route del default dev awg0 table 202 metric 100",
		"-4 rule del priority 1002 fwmark 0x202/0xffffffff lookup 202",
		"-6 rule del priority 1002 fwmark 0x202/0xffffffff lookup 202",
		"-4 route del unreachable default table 202 metric 32767",
		"-6 route del unreachable default table 202 metric 32767",
	}
	if strings.Join(last, "|") != strings.Join(want, "|") {
		t.Fatalf("unexpected teardown sequence: %#v", last)
	}
	runner = cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "default dev eth0 metric 50"
	before := len(runner.calls)
	if err := NewRoutePolicy(runner).Teardown(context.Background(), func(context.Context) error { return nil }); err == nil {
		t.Fatal("Teardown accepted an unowned route")
	}
	if len(runner.calls) != before+1 {
		t.Fatalf("Teardown mutated state after detecting an unowned route: %#v", runner.calls)
	}
}

// cleanRouteRunner returns fake empty routing state and the normal host interfaces.
func cleanRouteRunner() *fakeRouteRunner {
	return &fakeRouteRunner{outputs: map[string]string{"-o link show": "1: lo: <LOOPBACK>\n2: lima0: <UP>"}, fail: map[string]bool{}}
}
