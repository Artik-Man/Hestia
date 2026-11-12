//go:build linux && keenetic && netlinktest

package keeneticroute

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// TestLinuxIngressNetlinkMutations exercises route and RPDB mutations only in a namespace created by this test.
func TestLinuxIngressNetlinkMutations(t *testing.T) {
	if os.Getenv("HESTIA_NETLINK_TEST") != "1" {
		t.Skip("set HESTIA_NETLINK_TEST=1 to run in a self-created disposable network namespace")
	}
	if os.Getenv("HESTIA_NETLINK_TEST_CHILD") == "1" {
		marker := os.NewFile(3, "netns-test-marker")
		if marker == nil {
			t.Fatal("isolated test marker is missing")
		}
		data, err := io.ReadAll(io.LimitReader(marker, 64))
		_ = marker.Close()
		if err != nil || string(data) != "hestia-disposable-netns-v1\n" {
			t.Fatal("test child was not launched by its namespace wrapper")
		}
		parentNamespace := os.Getenv("HESTIA_NETLINK_PARENT_NS")
		currentNamespace, err := os.Readlink("/proc/self/ns/net")
		if err != nil || parentNamespace == "" || currentNamespace == parentNamespace {
			t.Fatalf("test child is not in a namespace created by its wrapper: parent=%q child=%q err=%v", parentNamespace, currentNamespace, err)
		}
		exerciseLinuxIngressNetlink(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Fatal("unshare is required to create the disposable network namespace")
	}
	parentNamespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("cannot inspect parent network namespace: %v", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("cannot create disposable-namespace marker: %v", err)
	}
	if _, err := writer.Write([]byte("hestia-disposable-netns-v1\n")); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		t.Fatalf("cannot write disposable-namespace marker: %v", err)
	}
	if err := writer.Close(); err != nil {
		_ = reader.Close()
		t.Fatalf("cannot close disposable-namespace marker: %v", err)
	}
	command := exec.Command(unshare, "--net", "--", os.Args[0], "-test.run=^TestLinuxIngressNetlinkMutations$", "-test.v")
	command.ExtraFiles = []*os.File{reader}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "HESTIA_NETLINK_TEST=") && !strings.HasPrefix(item, "HESTIA_NETLINK_TEST_CHILD=") && !strings.HasPrefix(item, "HESTIA_NETLINK_PARENT_NS=") {
			command.Env = append(command.Env, item)
		}
	}
	command.Env = append(command.Env, "HESTIA_NETLINK_TEST=1", "HESTIA_NETLINK_TEST_CHILD=1", "HESTIA_NETLINK_PARENT_NS="+parentNamespace)
	output, err := command.CombinedOutput()
	_ = reader.Close()
	t.Logf("disposable namespace test output:\n%s", output)
	if err != nil {
		t.Fatalf("disposable network namespace test failed: %v", err)
	}
}

// exerciseLinuxIngressNetlink checks real kernel operations after the wrapper proves it created a separate network namespace.
func exerciseLinuxIngressNetlink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("Linux route-netlink integration test requires root in its disposable namespace")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Fatal("iproute2 is required to create isolated dummy interfaces")
	}
	runIP := func(arguments ...string) error {
		output, commandErr := exec.Command(ip, arguments...).CombinedOutput()
		if commandErr != nil {
			return fmt.Errorf("ip %s failed: %s", strings.Join(arguments, " "), strings.TrimSpace(string(output)))
		}
		return nil
	}

	ctx := context.Background()
	ownershipDirectory, err := os.MkdirTemp("", "hestia-ingress-state-")
	if err != nil {
		t.Fatalf("cannot create isolated ownership directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(ownershipDirectory); err != nil {
			t.Errorf("cannot remove isolated ownership directory: %v", err)
		}
	})
	ops := NetlinkIngressOps{OwnershipPath: filepath.Join(ownershipDirectory, "rules.json")}
	mainRoutesBefore, err := ops.Routes(ctx, 254)
	if err != nil {
		t.Fatalf("cannot snapshot the isolated main route table: %v", err)
	}
	allRoutesBefore, err := ops.Routes(ctx, 0)
	if err != nil {
		t.Fatalf("cannot snapshot isolated routes: %v", err)
	}
	rulesBefore, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot decode baseline Linux policy rules: %v", err)
	}
	policy, err := NewIngressPolicy(ops, 30001, 0x0ffffabc, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	initialRoutes, err := ops.Routes(ctx, 30001)
	if err != nil || len(initialRoutes) != 0 {
		t.Fatalf("refusing to reuse a non-empty test route table: routes=%#v err=%v", initialRoutes, err)
	}
	for _, rule := range rulesBefore {
		if rule.Table == policy.table ||
			((rule.Priority == ingressRoutePriority || rule.Priority == ingressBlockPriority) && policy.selectorMayMatch(rule)) {
			t.Fatalf("refusing to reuse a pre-existing test policy rule: %+v", rule)
		}
	}
	for _, name := range []string{"br0", "opkgtun0"} {
		if err := runIP("link", "show", "dev", name); err == nil {
			t.Fatalf("refusing to reuse pre-existing interface %s", name)
		}
	}

	createdLinks := make(map[string]bool)
	for _, name := range []string{"br0", "opkgtun0"} {
		if err := runIP("link", "add", name, "type", "dummy"); err != nil {
			t.Fatal(err)
		}
		createdLinks[name] = true
		name := name
		t.Cleanup(func() {
			if createdLinks[name] {
				if err := runIP("link", "del", "dev", name); err != nil {
					t.Errorf("cannot remove test interface %s: %v", name, err)
				}
			}
		})
		if err := runIP("link", "set", "dev", name, "up"); err != nil {
			t.Fatal(err)
		}
	}
	policyRemoved := false
	t.Cleanup(func() {
		if !policyRemoved {
			if err := policy.Remove(context.Background()); err != nil {
				t.Errorf("cannot remove partial test policy state: %v", err)
			}
		}
	})
	if err := policy.InstallGuard(ctx); err != nil {
		t.Fatalf("cannot install route-netlink guard: %v", err)
	}
	guardRoutes, err := ops.Routes(ctx, 30001)
	if err != nil || len(guardRoutes) != 1 || guardRoutes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("unready route table must contain only its floor guard: routes=%#v err=%v", guardRoutes, err)
	}
	if err := policy.ActivateIPv4(ctx); err != nil {
		t.Fatalf("cannot activate route-netlink TUN default: %v", err)
	}
	routes, err := ops.Routes(ctx, 30001)
	if err != nil {
		t.Fatalf("cannot read back test route table: %v", err)
	}
	for _, expected := range []ingressRoute{policy.tunnelRoute(), policy.guardRoute(ingressGuardMetric)} {
		found := false
		for _, route := range routes {
			if route == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("kernel route dump does not contain expected route %#v: %#v", expected, routes)
		}
	}
	rules, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot read back test policy rules: %v", err)
	}
	for _, expected := range []ingressRule{policy.lookupRule, policy.blockRule, policy.ipv6Rule} {
		found := false
		for _, rule := range rules {
			if rule.Owned && sameIngressRuleIdentity(rule, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("kernel rule dump does not contain expected rule %+v", expected)
		}
	}
	if err := policy.DeactivateIPv4(ctx); err != nil {
		t.Fatalf("cannot restore guarded policy state: %v", err)
	}
	guardRoutes, err = ops.Routes(ctx, 30001)
	if err != nil || len(guardRoutes) != 1 || guardRoutes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("deactivation must remove the TUN route and restore its floor guard: routes=%#v err=%v", guardRoutes, err)
	}
	if err := policy.Remove(ctx); err != nil {
		t.Fatalf("cannot remove test policy state: %v", err)
	}
	policyRemoved = true
	if err := runIP("link", "del", "dev", "opkgtun0"); err != nil {
		t.Fatalf("cannot remove test TUN link: %v", err)
	}
	createdLinks["opkgtun0"] = false
	if err := runIP("link", "del", "dev", "br0"); err != nil {
		t.Fatalf("cannot remove test ingress link: %v", err)
	}
	createdLinks["br0"] = false
	mainRoutesAfter, err := ops.Routes(ctx, 254)
	if err != nil {
		t.Fatalf("cannot verify isolated main route table: %v", err)
	}
	allRoutesAfter, err := ops.Routes(ctx, 0)
	if err != nil {
		t.Fatalf("cannot verify isolated route cleanup: %v", err)
	}
	if !reflect.DeepEqual(mainRoutesBefore, mainRoutesAfter) || !reflect.DeepEqual(allRoutesBefore, allRoutesAfter) {
		t.Fatalf("Hestia ingress did not restore initial routes: main-before=%#v main-after=%#v all-before=%#v all-after=%#v", mainRoutesBefore, mainRoutesAfter, allRoutesBefore, allRoutesAfter)
	}
	rulesAfter, err := ops.Rules(ctx)
	if err != nil || !reflect.DeepEqual(rulesBefore, rulesAfter) {
		t.Fatalf("Hestia ingress did not restore initial rules: before=%#v after=%#v err=%v", rulesBefore, rulesAfter, err)
	}
	remainingRoutes, err := ops.Routes(ctx, 30001)
	if err != nil || len(remainingRoutes) != 0 {
		t.Fatalf("test route table was not emptied: routes=%#v err=%v", remainingRoutes, err)
	}
}

// TestKeeneticIngressRuleOwnershipOnTarget checks persisted rule ownership directly on a target kernel without selecting live traffic.
func TestKeeneticIngressRuleOwnershipOnTarget(t *testing.T) {
	if os.Getenv("HESTIA_TARGET_RULE_TEST") != "1" {
		t.Skip("set HESTIA_TARGET_RULE_TEST=1 only on the authorized Keenetic target")
	}
	if os.Geteuid() != 0 {
		t.Fatal("target RPDB ownership test requires root")
	}
	statePath := os.Getenv("HESTIA_INGRESS_RULE_STATE_PATH")
	if statePath == "" {
		t.Fatal("target RPDB ownership state path is required")
	}
	ctx := context.Background()
	ops := NetlinkIngressOps{OwnershipPath: statePath}
	routesBefore, err := ops.Routes(ctx, 0)
	if err != nil {
		t.Fatalf("cannot inspect target routes before ownership probe: %v", err)
	}
	rulesBefore, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot inspect target rules before ownership probe: %v", err)
	}
	rule := ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: 0x0ffffffe, Mask: 0xffffffff, Table: 34094, Action: ingressRuleLookup, Input: "lo", HasMark: true}
	tableBefore, err := ops.Routes(ctx, rule.Table)
	if err != nil || len(tableBefore) != 0 {
		t.Fatalf("refusing to reuse non-empty target test table: routes=%#v err=%v", tableBefore, err)
	}
	for _, existing := range rulesBefore {
		if existing.Priority == rule.Priority && ((existing.Mark^rule.Mark)&existing.Mask) == 0 &&
			(existing.Input == "" || existing.Input == rule.Input) {
			t.Fatalf("target priority already has a potentially matching rule: %+v", existing)
		}
		if sameIngressRuleIdentity(existing, rule) {
			t.Fatalf("target already has the exact ownership probe rule: %+v", existing)
		}
	}
	installed := false
	t.Cleanup(func() {
		if !installed {
			return
		}
		current, inspectErr := ops.Rules(context.Background())
		if inspectErr != nil {
			t.Errorf("cannot inspect target probe rule during cleanup: %v", inspectErr)
			return
		}
		for _, candidate := range current {
			if !targetProbeRuleMatches(candidate, rule) {
				continue
			}
			if candidate.Owned {
				if deleteErr := ops.DeleteRule(context.Background(), candidate); deleteErr != nil {
					t.Errorf("cannot remove owned target probe rule: %v", deleteErr)
				}
				return
			}
			if deleteErr := sendIngressNetlink(context.Background(), syscall.RTM_DELRULE, ruleNetlinkPayload(rule), false); deleteErr != nil {
				t.Errorf("cannot remove the exact probe rule created by this test: %v", deleteErr)
			}
			return
		}
	})
	if err := ops.AddRule(ctx, rule); err != nil {
		t.Fatalf("cannot add non-matching target ownership probe rule: %v", err)
	}
	installed = true
	active, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot read back target probe rule: %v", err)
	}
	var owned ingressRule
	for _, candidate := range active {
		if candidate.Owned && sameIngressRuleIdentity(candidate, rule) {
			owned = candidate
			break
		}
	}
	if !owned.Owned {
		t.Fatalf("new target RPDB rule was not linked to its persisted ownership record: expected=%+v observed=%+v", rule, active)
	}
	if err := (NetlinkIngressOps{OwnershipPath: statePath}).DeleteRule(ctx, owned); err != nil {
		t.Fatalf("cannot remove target ownership probe rule: %v", err)
	}
	installed = false
	rulesAfter, err := ops.Rules(ctx)
	if err != nil || !reflect.DeepEqual(rulesBefore, rulesAfter) {
		t.Fatalf("target RPDB did not return to its original state: before=%#v after=%#v err=%v", rulesBefore, rulesAfter, err)
	}
	routesAfter, err := ops.Routes(ctx, 0)
	if err != nil || !reflect.DeepEqual(routesBefore, routesAfter) {
		t.Fatalf("target routes changed during rule-only probe: before=%#v after=%#v err=%v", routesBefore, routesAfter, err)
	}
	tableAfter, err := ops.Routes(ctx, rule.Table)
	if err != nil || len(tableAfter) != 0 {
		t.Fatalf("target test table did not return to empty: routes=%#v err=%v", tableAfter, err)
	}
	state, err := readOwnedIngressRules(statePath)
	if err != nil || len(state) != 0 {
		t.Fatalf("target ownership state did not clear after rule deletion: rules=%#v err=%v", state, err)
	}
}

// TestKeeneticIngressPolicyInstallRemoveOnTarget exercises the real guard route and owned RPDB cleanup without a client policy.
func TestKeeneticIngressPolicyInstallRemoveOnTarget(t *testing.T) {
	if os.Getenv("HESTIA_TARGET_POLICY_TEST") != "1" {
		t.Skip("set HESTIA_TARGET_POLICY_TEST=1 only on the authorized Keenetic target")
	}
	if os.Geteuid() != 0 {
		t.Fatal("target ingress policy test requires root")
	}
	statePath := os.Getenv("HESTIA_INGRESS_RULE_STATE_PATH")
	if statePath == "" {
		t.Fatal("target RPDB ownership state path is required")
	}
	ctx := context.Background()
	ops := NetlinkIngressOps{OwnershipPath: statePath}
	allRoutesBefore, err := ops.Routes(ctx, 0)
	if err != nil {
		t.Fatalf("cannot inspect target routes before policy test: %v", err)
	}
	rulesBefore, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot inspect target rules before policy test: %v", err)
	}
	table, err := IngressTableForMark(0x0ffffffe)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewIngressPolicy(ops, table, 0x0ffffffe, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	tableBefore, err := ops.Routes(ctx, table)
	if err != nil || len(tableBefore) != 0 {
		t.Fatalf("refusing to reuse non-empty target test table: routes=%#v err=%v", tableBefore, err)
	}
	for _, rule := range rulesBefore {
		if rule.Table == table || ((rule.Priority == ingressRoutePriority || rule.Priority == ingressBlockPriority) && policy.selectorMayMatch(rule)) {
			t.Fatalf("refusing to reuse a potentially matching target rule: %+v", rule)
		}
	}
	removed := false
	t.Cleanup(func() {
		if removed {
			return
		}
		if removeErr := policy.Remove(context.Background()); removeErr != nil {
			t.Errorf("cannot remove target Hestia ingress policy test state: %v", removeErr)
		}
	})
	if err := policy.InstallGuard(ctx); err != nil {
		t.Fatalf("cannot install target guarded policy state: %v", err)
	}
	guardRoutes, err := ops.Routes(ctx, table)
	if err != nil || len(guardRoutes) != 1 || guardRoutes[0] != policy.guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("target guard route differs from expected: routes=%#v err=%v", guardRoutes, err)
	}
	rulesDuring, err := ops.Rules(ctx)
	if err != nil {
		t.Fatalf("cannot inspect owned target rules: %v", err)
	}
	for _, expected := range []ingressRule{policy.blockRule, policy.ipv6Rule, policy.lookupRule} {
		found := false
		for _, current := range rulesDuring {
			if current.Owned && sameIngressRuleIdentity(current, expected) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("target did not persist ownership of the expected RPDB rule %+v; rules=%+v", expected, rulesDuring)
		}
	}
	if err := policy.Remove(ctx); err != nil {
		t.Fatalf("cannot remove target guarded policy state: %v", err)
	}
	removed = true
	routesAfter, err := ops.Routes(ctx, 0)
	if err != nil || !reflect.DeepEqual(allRoutesBefore, routesAfter) {
		t.Fatalf("target routes differ after guarded policy removal: before=%#v after=%#v err=%v", allRoutesBefore, routesAfter, err)
	}
	rulesAfter, err := ops.Rules(ctx)
	if err != nil || !reflect.DeepEqual(rulesBefore, rulesAfter) {
		t.Fatalf("target RPDB differs after guarded policy removal: before=%#v after=%#v err=%v", rulesBefore, rulesAfter, err)
	}
	state, err := readOwnedIngressRules(statePath)
	if err != nil || len(state) != 0 {
		t.Fatalf("target ownership registry was not empty after policy removal: rules=%#v err=%v", state, err)
	}
}

// targetProbeRuleMatches identifies only the unique non-matching selector installed by the target ownership test.
func targetProbeRuleMatches(actual, expected ingressRule) bool {
	return actual.Family == expected.Family && actual.Priority == expected.Priority &&
		actual.Mark == expected.Mark && actual.Mask == expected.Mask && actual.Table == expected.Table &&
		actual.Action == expected.Action && actual.Input == expected.Input && actual.HasMark == expected.HasMark &&
		actual.SourcePrefixBits == 0 && actual.DestPrefixBits == 0 && actual.TOS == 0 &&
		(actual.Flags == 0 || actual.Flags == 8)
}
