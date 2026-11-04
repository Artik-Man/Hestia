package awg

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

const (
	policyMark     = "0x202"
	policyTable    = "202"
	policyPriority = "1002"
	awgInterface   = "awg0"
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
	runner RouteRunner
}

// NewRoutePolicy binds an injected command runner to the fixed first-release AWG policy values.
func NewRoutePolicy(runner RouteRunner) RoutePolicy {
	return RoutePolicy{runner: runner}
}

// Preflight rejects occupied priorities, overlapping marks, the reserved route table, or an existing awg0 device.
func (p RoutePolicy) Preflight(ctx context.Context) error {
	if p.runner == nil {
		return errors.New("AWG route runner is unavailable")
	}
	for _, family := range []string{"-4", "-6"} {
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect routing rules")
		}
		if err := inspectRules(string(rules), policyMark, policyPriority); err != nil {
			return err
		}
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", policyTable)
		if err != nil || strings.TrimSpace(string(routes)) != "" {
			return errors.New("AWG route table is occupied")
		}
	}
	links, err := p.runner.Run(ctx, "-o", "link", "show")
	if err != nil {
		return errors.New("cannot inspect network interfaces")
	}
	if hasInterface(string(links), awgInterface) {
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
	if _, err := p.runner.Run(ctx, "-4", "route", "add", "unreachable", "default", "table", policyTable, "metric", "32767"); err != nil {
		if !p.exactGuardExists(ctx, "-4") {
			return errors.New("cannot install IPv4 AWG fail-closed route")
		}
	}
	if _, err := p.runner.Run(ctx, "-6", "route", "add", "unreachable", "default", "table", policyTable, "metric", "32767"); err != nil {
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
		if _, err := p.runner.Run(ctx, family, "rule", "add", "priority", policyPriority, "fwmark", policyMark+"/0xffffffff", "lookup", policyTable); err != nil {
			if family == "-6" {
				_ = p.runnerRemove(ctx, "-4", "rule", "del", "priority", policyPriority, "fwmark", policyMark+"/0xffffffff", "lookup", policyTable)
			}
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
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", policyTable)
		if err != nil {
			return errors.New("cannot inspect the AWG route table")
		}
		if _, err := inspectOwnedRoutes(string(routes), allowTunnel && family == "-4"); err != nil {
			return err
		}
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect AWG routing rules")
		}
		if _, err := inspectOwnedRule(string(rules)); err != nil {
			return err
		}
	}
	return nil
}

// exactGuardExists confirms one family has only the expected unreachable guard in the reserved table.
func (p RoutePolicy) exactGuardExists(ctx context.Context, family string) bool {
	routes, err := p.runner.Run(ctx, family, "route", "show", "table", policyTable)
	if err != nil {
		return false
	}
	owned, err := inspectOwnedRoutes(string(routes), family == "-4")
	return err == nil && owned["guard"]
}

// exactMarkRuleExists confirms that a family has the exact owned mark lookup rule.
func (p RoutePolicy) exactMarkRuleExists(ctx context.Context, family string) bool {
	rules, err := p.runner.Run(ctx, family, "rule", "show")
	if err != nil {
		return false
	}
	found, err := inspectOwnedRule(string(rules))
	return err == nil && found
}

// ActivateIPv4 adds an AWG default only after the connector reports readiness; IPv6 remains unreachable.
func (p RoutePolicy) ActivateIPv4(ctx context.Context) error {
	if err := p.verifyReadyPolicy(ctx); err != nil {
		return err
	}
	links, err := p.runner.Run(ctx, "-o", "link", "show")
	if err != nil || !hasInterface(string(links), awgInterface) {
		return errors.New("AWG interface is not present")
	}
	if _, err := p.runner.Run(ctx, "-4", "route", "add", "default", "dev", awgInterface, "table", policyTable, "metric", "100"); err != nil {
		return errors.New("cannot activate IPv4 AWG route")
	}
	return nil
}

// verifyGuards requires both unreachable routes before installing either family’s packet-mark rule.
func (p RoutePolicy) verifyGuards(ctx context.Context) error {
	for _, family := range []string{"-4", "-6"} {
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", policyTable)
		if err != nil || !strings.Contains(string(routes), "unreachable default") || !strings.Contains(string(routes), "32767") {
			return errors.New("IPv4 and IPv6 AWG fail-closed guards must be installed first")
		}
	}
	return nil
}

// verifyReadyPolicy requires the exact mark rules and both family guards before activating the IPv4 tunnel route.
func (p RoutePolicy) verifyReadyPolicy(ctx context.Context) error {
	if err := p.verifyGuards(ctx); err != nil {
		return err
	}
	for _, family := range []string{"-4", "-6"} {
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil || !hasExpectedRule(string(rules)) {
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
		routes, err := p.runner.Run(ctx, family, "route", "show", "table", policyTable)
		if err != nil {
			return errors.New("cannot inspect AWG routes before teardown")
		}
		owned, err := inspectOwnedRoutes(string(routes), family == "-4")
		if err != nil {
			return err
		}
		routePresent[family] = owned
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect AWG mark rules before teardown")
		}
		present, err := inspectOwnedRule(string(rules))
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
		{"-4", "tunnel", []string{"-4", "route", "del", "default", "dev", awgInterface, "table", policyTable, "metric", "100"}},
		{"-4", "rule", []string{"-4", "rule", "del", "priority", policyPriority, "fwmark", policyMark + "/0xffffffff", "lookup", policyTable}},
		{"-6", "rule", []string{"-6", "rule", "del", "priority", policyPriority, "fwmark", policyMark + "/0xffffffff", "lookup", policyTable}},
		{"-4", "guard", []string{"-4", "route", "del", "unreachable", "default", "table", policyTable, "metric", "32767"}},
		{"-6", "guard", []string{"-6", "route", "del", "unreachable", "default", "table", policyTable, "metric", "32767"}},
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
func inspectOwnedRoutes(routes string, allowTunnel bool) (map[string]bool, error) {
	owned := map[string]bool{"tunnel": false, "guard": false}
	for _, line := range strings.Split(routes, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch line {
		case "unreachable default metric 32767":
			owned["guard"] = true
		case "default dev " + awgInterface + " metric 100":
			if !allowTunnel {
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
func inspectOwnedRule(rules string) (bool, error) {
	found := false
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		priority := rulePriorityPattern.FindStringSubmatch(line)
		if len(priority) == 2 && priority[1] == policyPriority {
			if !hasExpectedRule(line) {
				return false, errors.New("AWG rule priority contains an unowned rule; refusing teardown")
			}
			found = true
			continue
		}
		match := fwmarkPattern.FindStringSubmatch(line)
		if len(match) == 2 {
			parts := strings.Split(match[1], "/")
			value, err := strconv.ParseUint(parts[0], 0, 32)
			mask := uint64(0xffffffff)
			if len(parts) == 2 {
				mask, err = strconv.ParseUint(parts[1], 0, 32)
			}
			mark, parseErr := strconv.ParseUint(policyMark, 0, 32)
			if err != nil || parseErr != nil || len(parts) > 2 {
				return false, errors.New("cannot safely inspect packet marks before teardown")
			}
			if value&mask == mark&mask {
				return false, errors.New("AWG packet mark is used by an unowned rule; refusing teardown")
			}
		}
	}
	return found, nil
}

// inspectRules rejects use of the reserved priority and any existing mark mask that overlaps 0x202.
func inspectRules(rules, mark, priority string) error {
	markValue, err := strconv.ParseUint(mark, 0, 32)
	if err != nil {
		return errors.New("invalid configured AWG mark")
	}
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if match := rulePriorityPattern.FindStringSubmatch(line); len(match) == 2 && match[1] == priority {
			return errors.New("AWG routing priority is occupied")
		}
		match := fwmarkPattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		parts := strings.Split(match[1], "/")
		value, parseErr := strconv.ParseUint(parts[0], 0, 32)
		if parseErr != nil {
			return errors.New("cannot safely inspect existing packet marks")
		}
		mask := uint64(0xffffffff)
		if len(parts) == 2 {
			mask, parseErr = strconv.ParseUint(parts[1], 0, 32)
			if parseErr != nil {
				return errors.New("cannot safely inspect existing packet marks")
			}
		}
		if len(parts) > 2 || value&mask == markValue&mask {
			return errors.New("AWG packet mark conflicts with an existing rule")
		}
	}
	return nil
}

// hasExpectedRule recognizes the exact reserved mark lookup without relying on unrelated rule formatting.
func hasExpectedRule(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		line = strings.TrimSpace(line)
		if match := rulePriorityPattern.FindStringSubmatch(line); len(match) == 2 && match[1] == policyPriority && strings.Contains(line, "lookup "+policyTable) {
			marks := fwmarkPattern.FindStringSubmatch(line)
			if len(marks) == 2 && marks[1] == policyMark+"/0xffffffff" {
				return true
			}
		}
	}
	return false
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

// runnerRemove performs best-effort rollback without exposing command output.
func (p RoutePolicy) runnerRemove(ctx context.Context, args ...string) error {
	_, err := p.runner.Run(ctx, args...)
	return err
}
