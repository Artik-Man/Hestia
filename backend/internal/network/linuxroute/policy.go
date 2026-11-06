package linuxroute

import (
	"context"
	"errors"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/network"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

var (
	rulePriorityPattern = regexp.MustCompile(`^([0-9]+):`)
	fwmarkPattern       = regexp.MustCompile(`\bfwmark\s+([^\s]+)`)
)

// RouteRunner executes one fixed iproute2 command and returns its output for structural preflight checks.
type RouteRunner interface {
	Run(context.Context, ...string) ([]byte, error)
}

// RoutePolicy manages only the AWG mark/table rules and never changes the main routing table.
type RoutePolicy struct {
	runner        RouteRunner
	mark          string
	table         string
	priority      string
	priorityValue int
	device        string
	markValue     int
}

// NewRoutePolicy binds an injected command runner to the legacy slot-zero AWG policy.
func NewRoutePolicy(runner RouteRunner) RoutePolicy {
	policy, _ := NewSlotPolicy(runner, 0)
	return policy
}

// NewSlotPolicy derives a disjoint IPv4/IPv6 policy for one validated persistent allocation.
func NewSlotPolicy(runner RouteRunner, slot int) (RoutePolicy, error) {
	if slot < 0 || slot >= network.SlotCount {
		return RoutePolicy{}, errors.New("invalid AWG runtime slot")
	}
	return RoutePolicy{
		runner: runner, markValue: 0x202 + slot, priorityValue: 1002 + slot,
		mark:  fmt.Sprintf("0x%x", 0x202+slot),
		table: strconv.Itoa(202 + slot), priority: strconv.Itoa(1002 + slot),
		device: "awg" + strconv.Itoa(slot),
	}, nil
}

// Preflight rejects occupied priorities, overlapping marks, the reserved route table, or an existing slot device.
func (p RoutePolicy) Preflight(ctx context.Context) error {
	if p.runner == nil {
		return errors.New("AWG route runner is unavailable")
	}
	for _, family := range []string{"-4", "-6"} {
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect routing rules")
		}
		owned, err := p.inspectOwnedRule(string(rules))
		if err != nil {
			return err
		}
		if owned {
			return errors.New("AWG routing priority is occupied")
		}
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", p.table)
		if err != nil || strings.TrimSpace(string(routes)) != "" {
			return errors.New("AWG route table is occupied")
		}
	}
	links, err := p.runner.Run(ctx, "-o", "link", "show")
	if err != nil {
		return errors.New("cannot inspect network interfaces")
	}
	if hasInterface(string(links), p.device) {
		return errors.New("AWG interface name is already occupied")
	}
	return nil
}

// InstallGuard installs IPv4 and IPv6 unreachable defaults before adding any mark rules.
// IPv6 stays blocked in this IPv4-only release, including when a group outbound carries an IPv6 flow.
func (p RoutePolicy) InstallGuard(ctx context.Context) error {
	if err := p.Preflight(ctx); err != nil {
		return err
	}
	return p.EnsureGuards(ctx)
}

// EnsureGuards idempotently installs the exact IPv4 and IPv6 unreachable defaults after preflight or owned-state adoption.
func (p RoutePolicy) EnsureGuards(ctx context.Context) error {
	if err := p.inspectPolicyState(ctx, false); err != nil {
		return err
	}
	if _, err := p.runner.Run(ctx, "-4", "route", "add", "unreachable", "default", "table", p.table, "metric", "32767"); err != nil {
		if !p.exactGuardExists(ctx, "-4") {
			return errors.New("cannot install IPv4 AWG fail-closed route")
		}
	}
	if _, err := p.runner.Run(ctx, "-6", "route", "add", "unreachable", "default", "table", p.table, "metric", "32767"); err != nil {
		if !p.exactGuardExists(ctx, "-6") {
			return errors.New("cannot install IPv6 AWG fail-closed route")
		}
	}
	return nil
}

// InstallMarkRules sends marked IPv4 and IPv6 flows to the guarded table before a usable AWG route exists.
func (p RoutePolicy) InstallMarkRules(ctx context.Context) error {
	if err := p.verifyGuards(ctx); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		if p.exactMarkRuleExists(ctx, family) {
			continue
		}
		if _, err := p.runner.Run(ctx, family, "rule", "add", "priority", p.priority, "fwmark", p.mark+"/0xffffffff", "lookup", p.table); err != nil {
			// Keep any existing family guarded until an explicit drained teardown.
			return errors.New("cannot install AWG fail-closed mark rule")
		}
	}
	return nil
}

// AdoptOwnedState validates route/table state against an external root-only ownership manifest before restart recovery.
func (p RoutePolicy) AdoptOwnedState(ctx context.Context) error {
	return p.inspectPolicyState(ctx, true)
}

// inspectPolicyState accepts empty state or exact AWG entries and rejects all unowned routes and priorities.
func (p RoutePolicy) inspectPolicyState(ctx context.Context, allowTunnel bool) error {
	for _, family := range []string{"-4", "-6"} {
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", p.table)
		if err != nil {
			return errors.New("cannot inspect the AWG route table")
		}
		if _, err := p.inspectOwnedRoutes(string(routes), family, allowTunnel); err != nil {
			return err
		}
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect AWG routing rules")
		}
		if _, err := p.inspectOwnedRule(string(rules)); err != nil {
			return err
		}
	}
	return nil
}

// exactGuardExists confirms one family has only the expected unreachable guard in the reserved table.
func (p RoutePolicy) exactGuardExists(ctx context.Context, family string) bool {
	routes, err := p.runner.Run(ctx, family, "route", "show", "table", p.table)
	if err != nil {
		return false
	}
	owned, err := p.inspectOwnedRoutes(string(routes), family, true)
	return err == nil && owned["guard"]
}

// exactMarkRuleExists confirms that a family has the exact owned mark lookup rule.
func (p RoutePolicy) exactMarkRuleExists(ctx context.Context, family string) bool {
	rules, err := p.runner.Run(ctx, family, "rule", "show")
	if err != nil {
		return false
	}
	found, err := p.inspectOwnedRule(string(rules))
	return err == nil && found
}

// ActivateIPv4 adds an AWG default only after the connector reports readiness; IPv6 remains unreachable.
func (p RoutePolicy) ActivateIPv4(ctx context.Context) error {
	if err := p.VerifyReadyPolicy(ctx); err != nil {
		return err
	}
	links, err := p.runner.Run(ctx, "-o", "link", "show")
	if err != nil || !hasInterface(string(links), p.device) {
		return errors.New("AWG interface is not present")
	}
	if _, err := p.runner.Run(ctx, "-4", "route", "add", "default", "dev", p.device, "table", p.table, "metric", "100"); err != nil {
		return errors.New("cannot activate IPv4 AWG route")
	}
	return nil
}

// verifyGuards requires both unreachable routes before installing either family’s packet-mark rule.
func (p RoutePolicy) verifyGuards(ctx context.Context) error {
	for _, family := range []string{"-4", "-6"} {
		if !p.exactGuardExists(ctx, family) {
			return errors.New("IPv4 and IPv6 AWG fail-closed guards must be installed first")
		}
	}
	return nil
}

// VerifyReadyPolicy requires the exact mark rules and both family guards before activating the IPv4 tunnel route.
func (p RoutePolicy) VerifyReadyPolicy(ctx context.Context) error {
	if err := p.verifyGuards(ctx); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		if !p.exactMarkRuleExists(ctx, family) {
			return errors.New("AWG packet-mark rules are not fully installed")
		}
	}
	return nil
}

// Teardown disables the marked sing-box outbound before removing rules and guards; a failed drain leaves the guard intact.
func (p RoutePolicy) Teardown(ctx context.Context, disableOutbound func(context.Context) error) error {
	if disableOutbound == nil {
		return errors.New("AWG outbound must be disabled before route teardown")
	}
	if err := disableOutbound(ctx); err != nil {
		return errors.New("cannot confirm AWG outbound is disabled; fail-closed routes retained")
	}
	routePresent := make(map[string]map[string]bool, 2)
	rulePresent := make(map[string]bool, 2)
	for _, family := range []string{"-4", "-6"} {
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", p.table)
		if err != nil {
			return errors.New("cannot inspect AWG routes before teardown")
		}
		owned, err := p.inspectOwnedRoutes(string(routes), family, true)
		if err != nil {
			return err
		}
		routePresent[family] = owned
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect AWG mark rules before teardown")
		}
		present, err := p.inspectOwnedRule(string(rules))
		if err != nil {
			return err
		}
		rulePresent[family] = present
	}
	steps := []struct {
		family string
		name   string
		args   []string
	}{
		{"-4", "tunnel", []string{"-4", "route", "del", "default", "dev", p.device, "table", p.table, "metric", "100"}},
		{"-4", "rule", []string{"-4", "rule", "del", "priority", p.priority, "fwmark", p.mark + "/0xffffffff", "lookup", p.table}},
		{"-6", "rule", []string{"-6", "rule", "del", "priority", p.priority, "fwmark", p.mark + "/0xffffffff", "lookup", p.table}},
		{"-4", "guard", []string{"-4", "route", "del", "unreachable", "default", "table", p.table, "metric", "32767"}},
		{"-6", "guard", []string{"-6", "route", "del", "unreachable", "default", "table", p.table, "metric", "32767"}},
	}
	for _, step := range steps {
		present := false
		if step.name == "rule" {
			present = rulePresent[step.family]
		} else {
			present = routePresent[step.family][step.name]
		}
		if !present {
			continue
		}
		if _, err := p.runner.Run(ctx, step.args...); err != nil {
			return errors.New("AWG route teardown incomplete; inspect owned routes before retrying")
		}
	}
	return nil
}

// inspectOwnedRoutes accepts only the exact AWG tunnel default and IPv4/IPv6 unreachable guard routes.
func (p RoutePolicy) inspectOwnedRoutes(routes, family string, allowTunnel bool) (map[string]bool, error) {
	owned := map[string]bool{"tunnel": false, "guard": false}
	for _, line := range strings.Split(routes, "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			continue
		}
		if family == "-6" {
			line = strings.TrimSuffix(line, " pref medium")
		}
		switch line {
		case "unreachable default metric 32767":
			owned["guard"] = true
		case "unreachable default dev lo metric 32767":
			if family != "-6" {
				return nil, errors.New("unexpected IPv4 AWG guard device")
			}
			owned["guard"] = true
		case "default dev " + p.device + " metric 100", "default dev " + p.device + " scope link metric 100":
			if !allowTunnel || family != "-4" {
				return nil, errors.New("unexpected IPv6 AWG tunnel route; refusing teardown")
			}
			owned["tunnel"] = true
		default:
			return nil, errors.New("AWG route table contains an unowned route; refusing teardown")
		}
	}
	return owned, nil
}

// inspectOwnedRule finds the exact reserved mark rule and refuses a different rule at its priority or mark.
func (p RoutePolicy) inspectOwnedRule(rules string) (bool, error) {
	found := false
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		matchPriority := rulePriorityPattern.FindStringSubmatch(line)
		if len(matchPriority) != 2 {
			return false, errors.New("cannot verify AWG routing rule priority")
		}
		priority, err := strconv.ParseUint(matchPriority[1], 10, 32)
		if err != nil {
			return false, errors.New("cannot verify AWG routing rule priority")
		}
		if int(priority) == p.priorityValue {
			if found || !p.hasExpectedRule(line) {
				return false, errors.New("AWG rule priority contains an unowned rule; refusing teardown")
			}
			found = true
			continue
		}
		fields := strings.Fields(line)
		for i, field := range fields {
			if (field == "lookup" || field == "table") && i+1 < len(fields) && fields[i+1] == p.table {
				return false, errors.New("AWG table is used by an unowned rule")
			}
		}
		match := fwmarkPattern.FindStringSubmatch(line)
		if priority < uint64(p.priorityValue) && !safeEarlierRule(fields, len(match) == 2) {
			return false, errors.New("an earlier routing rule can bypass the AWG guard")
		}
		if len(match) == 2 {
			parts := strings.Split(match[1], "/")
			value, err := strconv.ParseUint(parts[0], 0, 32)
			if err != nil || len(parts) > 2 {
				return false, errors.New("cannot safely inspect packet marks before teardown")
			}
			mask := uint64(0xffffffff)
			if len(parts) == 2 {
				mask, err = strconv.ParseUint(parts[1], 0, 32)
			}
			if err != nil {
				return false, errors.New("cannot safely inspect packet marks before teardown")
			}
			if value&mask == uint64(p.markValue)&mask {
				return false, errors.New("AWG packet mark is used by an unowned rule; refusing teardown")
			}
		}
	}
	return found, nil
}

// safeEarlierRule accepts the kernel local lookup or selectors provably disjoint from local marked output.
// Callers separately verify the numeric mark and mask for every rule with a fwmark selector.
func safeEarlierRule(fields []string, hasMark bool) bool {
	if slices.Equal(fields, []string{"0:", "from", "all", "lookup", "local"}) ||
		slices.Equal(fields, []string{"0:", "from", "all", "lookup", "255"}) {
		return true
	}
	if slices.Contains(fields, "not") {
		return false
	}
	if hasMark {
		return true
	}
	for i, field := range fields {
		if field == "iif" && i+1 < len(fields) && fields[i+1] != "lo" {
			return true
		}
	}
	return false
}

// hasExpectedRule recognizes the exact reserved mark lookup without relying on unrelated rule formatting.
func (p RoutePolicy) hasExpectedRule(line string) bool {
	prefix := p.priority + ": from all fwmark " + p.mark
	lookup := " lookup " + p.table
	if p.table == "" {
		lookup = " unreachable"
	}
	normalized := strings.Join(strings.Fields(line), " ")
	return normalized == prefix+lookup || normalized == prefix+"/0xffffffff"+lookup
}

// hasInterface checks the interface-name token in `ip -o link show` output.
func hasInterface(links, name string) bool {
	for _, line := range strings.Split(links, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			interfaceName := strings.TrimSuffix(fields[1], ":")
			if interfaceName == name {
				return true
			}
		}
	}
	return false
}

// Descriptor returns the immutable allocation whose resources this adapter owns.
func (p RoutePolicy) Descriptor() network.RouteDescriptor {
	return network.RouteDescriptor{Mark: p.mark, Table: p.table, Priority: p.priority, Device: p.device, MarkValue: p.markValue}
}

// NewOuterPolicy derives the daemon's terminal mark barrier for a validated slot.
func NewOuterPolicy(runner RouteRunner, slot int) (RoutePolicy, error) {
	if slot < 0 || slot >= network.SlotCount {
		return RoutePolicy{}, errors.New("invalid AWG runtime slot")
	}
	return RoutePolicy{runner: runner, markValue: 0x51000 + slot, mark: fmt.Sprintf("0x%x", 0x51000+slot), priorityValue: 1100 + slot, priority: strconv.Itoa(1100 + slot), device: "lo"}, nil
}

// OuterBarrier verifies ownership before publishing a record and changing only this slot's terminal rules.
// The caller persists ownership before mutation and retains it on partial failures.
func (p RoutePolicy) OuterBarrier(ctx context.Context, owned, install bool, publish func() error) error {
	present := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect WireGuard outer guard")
		}
		found, err := p.inspectOwnedRule(string(rules))
		if err != nil {
			return err
		}
		if found && !owned {
			return errors.New("WireGuard outer guard priority is occupied")
		}
		present[family] = found
	}
	if install && !owned {
		if err := publish(); err != nil {
			return err
		}
	}
	for _, family := range []string{"-4", "-6"} {
		if present[family] == install {
			continue
		}
		verb := "del"
		if install {
			verb = "add"
		}
		if _, err := p.runner.Run(ctx, family, "rule", verb, "priority", p.priority, "fwmark", p.mark+"/0xffffffff", "unreachable"); err != nil {
			return errors.New("cannot apply WireGuard outer guard")
		}
	}
	return nil
}
