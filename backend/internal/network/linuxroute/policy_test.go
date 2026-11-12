package linuxroute

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/network"
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
		fmt.Sprintf("%d: from all lookup 202", network.MarkRulePriority(0)),
		"1200: from all fwmark 0x200/0xff8 lookup 201",
		"1500: from 10.0.0.0/8 lookup 202",
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
	runner.outputs["-4 rule show"] = fmt.Sprintf("%d: from all fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0))
	runner.outputs["-6 rule show"] = fmt.Sprintf("%d: from all fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0))
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
	runner.outputs["-4 route show table 202"] = "default dev awg0 scope link metric 100\nunreachable default metric 32767"
	runner.outputs["-6 route show table 202"] = "unreachable default metric 32767"
	runner.outputs["-4 rule show"] = fmt.Sprintf("%d: from all fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0))
	runner.outputs["-6 rule show"] = fmt.Sprintf("%d: from all fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0))
	policy := NewRoutePolicy(runner)
	if err := policy.Teardown(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Teardown failed for exact owned state: %v", err)
	}
	last := runner.calls[len(runner.calls)-5:]
	want := []string{
		"-4 route del default dev awg0 table 202 metric 100",
		fmt.Sprintf("-4 rule del priority %d fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0)),
		fmt.Sprintf("-6 rule del priority %d fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0)),
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

// TestRoutePolicyIPRoute2Output verifies iproute2's mask shorthand and IPv6 loopback guard without admitting foreign selectors.
func TestRoutePolicyIPRoute2Output(t *testing.T) {
	runner := cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "unreachable default metric 32767"
	runner.outputs["-6 route show table 202"] = "unreachable default dev lo metric 32767 pref medium"
	for _, family := range []string{"-4", "-6"} {
		runner.outputs[family+" rule show"] = fmt.Sprintf("%d:\tfrom all fwmark 0x202 lookup 202", network.MarkRulePriority(0))
	}
	policy := NewRoutePolicy(runner)
	if err := policy.AdoptOwnedState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := policy.VerifyReadyPolicy(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.outputs["-6 route show table 202"] = "unreachable default dev lo metric 32767 error -113"
	if err := policy.AdoptOwnedState(context.Background()); err != nil {
		t.Fatalf("Keenetic IPv6 unreachable guard was not recognized as owned: %v", err)
	}
	for _, rule := range []string{fmt.Sprintf("%d: from all fwmark 0x202 lookup 2020", network.MarkRulePriority(0)), fmt.Sprintf("%d: from all fwmark 0x202 iif eth0 lookup 202", network.MarkRulePriority(0)), fmt.Sprintf("%d: from all fwmark 0x202/0x00ff lookup 202", network.MarkRulePriority(0))} {
		runner.outputs["-4 rule show"] = rule
		if err := policy.AdoptOwnedState(context.Background()); err == nil {
			t.Fatal("accepted foreign selector", rule)
		}
	}
}

// TestSecondTunnelPolicyIgnoresFirst checks a second slot can activate and retire without changing its neighbor.
func TestSecondTunnelPolicyIgnoresFirst(t *testing.T) {
	runner := cleanRouteRunner()
	for _, family := range []string{"-4", "-6"} {
		runner.outputs[family+" rule show"] = fmt.Sprintf("%d: from all fwmark 0x202 lookup 202\n%d: from all fwmark 0x203 lookup 203", network.MarkRulePriority(0), network.MarkRulePriority(1))
		runner.outputs[family+" route show table 203"] = "unreachable default metric 32767"
	}
	runner.outputs["-o link show"] = "7: awg0: <UP>\n8: awg1: <UP>"
	policy, err := NewSlotPolicy(runner, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.ActivateIPv4(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner.outputs["-4 route show table 203"] += "\ndefault dev awg1 metric 100"
	if err := policy.Teardown(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "awg0") || strings.Contains(call, "table 202") || strings.Contains(call, "0x202") {
			t.Fatalf("second policy touched first slot: %s", call)
		}
	}
}

// TestIncompleteSecondFamilyRetainsFirstRule protects an already guarded live IPv4 flow during IPv6 repair.
func TestIncompleteSecondFamilyRetainsFirstRule(t *testing.T) {
	runner := cleanRouteRunner()
	runner.outputs["-4 route show table 202"] = "unreachable default metric 32767"
	runner.outputs["-6 route show table 202"] = "unreachable default dev lo metric 32767"
	runner.outputs["-4 rule show"] = fmt.Sprintf("%d: from all fwmark 0x202 lookup 202", network.MarkRulePriority(0))
	runner.fail[fmt.Sprintf("-6 rule add priority %d fwmark 0x202/0xffffffff lookup 202", network.MarkRulePriority(0))] = true
	if err := NewRoutePolicy(runner).InstallMarkRules(context.Background()); err == nil {
		t.Fatal("accepted missing IPv6 rule")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "rule del") {
			t.Fatal("a failed IPv6 repair removed the IPv4 guard")
		}
	}
}

// TestEarlyPolicyRulesCannotBypassGuard covers ordinary host rules and earlier selectors for locally marked traffic.
func TestEarlyPolicyRulesCannotBypassGuard(t *testing.T) {
	for _, tc := range []struct {
		line string
		safe bool
	}{
		{"0: from all lookup local", true},
		{"0: from all lookup 255", true},
		{"1000: from all iif wg-keenetic lookup 200", true},
		{"1001: from all iif hestia0 lookup 201", true},
		{fmt.Sprintf("%d: from all fwmark 0x202 lookup 202", network.MarkRulePriority(0)), true},
		{"800: from all lookup main", false},
		{"800: from 10.0.0.0/8 lookup main", false},
		{"800: from all iif lo lookup main", false},
		{"800: not from all fwmark 0x202 lookup main", false},
		{"800: not from all iif hestia0 lookup main", false},
		{"800: from all fwmark 0x200/0xff8 lookup main", false},
	} {
		runner := cleanRouteRunner()
		runner.outputs["-4 rule show"] = tc.line
		policy, err := NewSlotPolicy(runner, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.Preflight(context.Background()); (err == nil) != tc.safe {
			t.Errorf("preflight rule %q safe=%t, err=%v", tc.line, tc.safe, err)
		}
		for _, family := range []string{"-4", "-6"} {
			runner.outputs[family+" route show table 203"] = "unreachable default metric 32767"
			runner.outputs[family+" rule show"] = tc.line + fmt.Sprintf("\n%d: from all fwmark 0x203 lookup 203", network.MarkRulePriority(1))
		}
		if err := policy.VerifyReadyPolicy(context.Background()); (err == nil) != tc.safe {
			t.Errorf("guard confirmation rule %q safe=%t, err=%v", tc.line, tc.safe, err)
		}
	}
}

// TestOuterBarrierPublishesOwnershipBeforeMutations preserves recovery across partial rule installation.
func TestOuterBarrierPublishesOwnershipBeforeMutations(t *testing.T) {
	runner := cleanRouteRunner()
	policy, err := NewOuterPolicy(runner, 1)
	if err != nil {
		t.Fatal(err)
	}
	published := false
	err = policy.OuterBarrier(context.Background(), false, true, func() error {
		for _, call := range runner.calls {
			if strings.Contains(call, "rule add") {
				t.Fatal("mutation preceded ownership")
			}
		}
		published = true
		return nil
	})
	if err != nil || !published {
		t.Fatalf("publish %v error %v", published, err)
	}
	if len(runner.calls) != 4 || runner.calls[2] != fmt.Sprintf("-4 rule add priority %d fwmark 0x51001/0xffffffff unreachable", network.OuterRulePriority(1)) || runner.calls[3] != fmt.Sprintf("-6 rule add priority %d fwmark 0x51001/0xffffffff unreachable", network.OuterRulePriority(1)) {
		t.Fatalf("calls %v", runner.calls)
	}
}

// TestOuterBarrierRejectsForeignRule refuses to claim an existing terminal rule without ownership.
func TestOuterBarrierRejectsForeignRule(t *testing.T) {
	runner := cleanRouteRunner()
	runner.outputs["-4 rule show"] = fmt.Sprintf("%d: from all fwmark 0x51000 unreachable", network.OuterRulePriority(0))
	policy, err := NewOuterPolicy(runner, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = policy.OuterBarrier(context.Background(), false, true, func() error { t.Fatal("claimed foreign rule"); return nil })
	if err == nil {
		t.Fatal("foreign rule accepted")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "rule add") {
			t.Fatal("mutated foreign rule")
		}
	}
}

// TestRouteAllocationBounds keeps adapter metadata consistent and rejects invalid slots before execution.
func TestRouteAllocationBounds(t *testing.T) {
	for _, slot := range []int{-1, 50} {
		if _, err := NewSlotPolicy(cleanRouteRunner(), slot); err == nil {
			t.Fatal("accepted invalid tunnel slot")
		}
		if _, err := NewOuterPolicy(cleanRouteRunner(), slot); err == nil {
			t.Fatal("accepted invalid outer slot")
		}
	}
	policy, err := NewSlotPolicy(cleanRouteRunner(), 1)
	if err != nil {
		t.Fatal(err)
	}
	d := policy.Descriptor()
	if d.Device != "awg1" || d.Mark != "0x203" || d.MarkValue != 515 || d.Table != "203" || d.Priority != fmt.Sprint(network.MarkRulePriority(1)) {
		t.Fatalf("descriptor %+v", d)
	}
}

// TestOwnedRulePriorityMigrationMovesOnlyTheDeclaredSlotRule keeps the guard route while changing its marked rule.
func TestOwnedRulePriorityMigrationMovesOnlyTheDeclaredSlotRule(t *testing.T) {
	runner := cleanRouteRunner()
	policy, err := NewSlotPolicy(runner, 0)
	if err != nil {
		t.Fatal(err)
	}
	if policy.priority == "1002" {
		return
	}
	for _, family := range []string{"-4", "-6"} {
		runner.outputs[family+" route show table 202"] = "unreachable default metric 32767"
		runner.outputs[family+" rule show"] = "1002: from all fwmark 0x202 lookup 202"
	}
	if err := policy.MigrateOwnedRulePriority(context.Background(), "1002"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-4 rule add priority " + policy.priority + " fwmark 0x202/0xffffffff lookup 202",
		"-6 rule add priority " + policy.priority + " fwmark 0x202/0xffffffff lookup 202",
		"-4 rule del priority 1002 fwmark 0x202/0xffffffff lookup 202",
		"-6 rule del priority 1002 fwmark 0x202/0xffffffff lookup 202",
	}
	for _, call := range want {
		if !strings.Contains(strings.Join(runner.calls, "\n"), call) {
			t.Errorf("migration did not issue %q; calls=%v", call, runner.calls)
		}
	}
}
