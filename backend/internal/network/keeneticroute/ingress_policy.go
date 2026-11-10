//go:build keenetic

package keeneticroute

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

const (
	ingressTableMinimum     = 30000
	ingressTableMaximum     = 34095
	ingressRoutePriority    = 7
	ingressBlockPriority    = 8
	ingressRouteMetric      = 1000
	ingressGuardMetric      = 32767
	ingressGuardFloorMetric = 0
	// KeeneticOS can mark an installed OpkgTun route link-down until sing-box attaches to the TUN device.
	ingressRouteFlagLinkDown = 16
	// 253 is a local route protocol used to identify only Hestia-owned ingress routes in kernel dumps.
	ingressRouteProtocol = 253
	ingressIPv4Family    = 2
	ingressIPv6Family    = 10
)

var ingressDevicePattern = regexp.MustCompile(`^opkgtun[0-9]{1,2}$`)
var ingressInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// IngressTableForMark assigns every observed Keenetic policy mark a stable, collision-free Hestia table ID.
func IngressTableForMark(mark uint32) (uint32, error) {
	if mark < 0x0ffff000 || mark > 0x0fffffff {
		return 0, errors.New("invalid Keenetic IPv4 policy mark")
	}
	return ingressTableMinimum + mark - 0x0ffff000, nil
}

type ingressRouteType uint8

const (
	ingressUnicast     ingressRouteType = 1
	ingressUnreachable ingressRouteType = 7
)

type ingressRuleAction uint8

const (
	ingressRuleLookup      ingressRuleAction = 1
	ingressRuleUnreachable ingressRuleAction = 7
)

type ingressRoute struct {
	Table              uint32
	PrefixBits         uint8
	SourcePrefixBits   uint8
	TOS                uint8
	Type               ingressRouteType
	Scope              uint8
	Protocol           uint8
	Flags              uint32
	Metric             uint32
	Device             string
	HasGateway         bool
	HasOtherAttributes bool
}

type ingressRule struct {
	Family            uint8
	Priority          uint32
	Protocol          uint8
	Mark              uint32
	Mask              uint32
	Table             uint32
	Action            ingressRuleAction
	Input             string
	SourcePrefixBits  uint8
	DestPrefixBits    uint8
	TOS               uint8
	Flags             uint32
	HasOtherSelectors bool
	HasMark           bool
	Owned             bool `json:"-"`
}

// ingressPolicyOps isolates route ownership logic from the raw Linux route-netlink transport.
type ingressPolicyOps interface {
	// Routes lists every IPv4 route currently installed in the requested table.
	Routes(context.Context, uint32) ([]ingressRoute, error)
	// Rules lists all IPv4 RPDB rules, including their mark and input-interface selectors.
	Rules(context.Context) ([]ingressRule, error)
	// LinkUp confirms that one exact Linux interface exists and is administratively up.
	LinkUp(context.Context, string) (bool, error)
	// AddRoute installs one exact IPv4 route and reports kernel errors without raw payloads.
	AddRoute(context.Context, ingressRoute) error
	// DeleteRoute removes one exact route that the policy adapter has already proven it owns.
	DeleteRoute(context.Context, ingressRoute) error
	// AddRule installs one exact IPv4 policy rule and reports kernel errors without raw payloads.
	AddRule(context.Context, ingressRule) error
	// DeleteRule removes one exact rule that the policy adapter has already proven it owns.
	DeleteRule(context.Context, ingressRule) error
}

// IngressPolicy redirects one Keenetic policy mark from LAN ingress into an isolated Hestia-owned route table.
type IngressPolicy struct {
	ops        ingressPolicyOps
	table      uint32
	mark       uint32
	ingress    string
	tunnel     string
	lookupRule ingressRule
	blockRule  ingressRule
	ipv6Rule   ingressRule
}

// NewIngressPolicy binds one RCI-provided mark to a reserved Hestia table and the exact LAN/TUN devices.
func NewIngressPolicy(ops ingressPolicyOps, table, mark uint32, ingress, tunnel string) (IngressPolicy, error) {
	if ops == nil || table < ingressTableMinimum || table > ingressTableMaximum ||
		mark < 0x0ffff000 || mark > 0x0fffffff || !ingressInterfacePattern.MatchString(ingress) ||
		!ingressDevicePattern.MatchString(tunnel) {
		return IngressPolicy{}, errors.New("invalid Keenetic ingress policy identity")
	}
	return IngressPolicy{
		ops: ops, table: table, mark: mark, ingress: ingress, tunnel: tunnel,
		lookupRule: ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: mark, Mask: 0xffffffff, Table: table, Action: ingressRuleLookup, Input: ingress, HasMark: true},
		blockRule:  ingressRule{Family: ingressIPv4Family, Priority: ingressBlockPriority, Mark: mark, Mask: 0xffffffff, Action: ingressRuleUnreachable, Input: ingress, HasMark: true},
		ipv6Rule:   ingressRule{Family: ingressIPv6Family, Priority: ingressRoutePriority, Mark: mark, Mask: 0xffffffff, Action: ingressRuleUnreachable, Input: ingress, HasMark: true},
	}, nil
}

// InstallGuard validates ownership, installs the blocking route and terminal rules, then publishes the IPv4 lookup rule last.
func (p IngressPolicy) InstallGuard(ctx context.Context) error {
	if err := p.Preflight(ctx); err != nil {
		return err
	}
	if err := p.ensureRule(ctx, p.blockRule); err != nil {
		if routeErr := p.ensureFloorGuard(ctx); routeErr != nil {
			return errors.New("cannot install the Hestia IPv4 fallback guard")
		}
		ipv6Err := p.ensureRule(ctx, p.ipv6Rule)
		if lookupErr := p.ensureRule(ctx, p.lookupRule); lookupErr != nil {
			return errors.New("cannot install either Hestia IPv4 blocking rule")
		}
		return ipv6Err
	}
	if err := p.ensureRule(ctx, p.ipv6Rule); err != nil {
		return err
	}
	if err := p.ensureFloorGuard(ctx); err != nil {
		return err
	}
	return p.ensureRule(ctx, p.lookupRule)
}

// ensureFloorGuard installs or confirms the lowest-metric unreachable default in Hestia's isolated table.
func (p IngressPolicy) ensureFloorGuard(ctx context.Context) error {
	routes, err := p.ops.Routes(ctx, p.table)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress table")
	}
	state, err := p.inspectRoutes(routes)
	if err != nil {
		return err
	}
	if !state[ingressGuardFloorMetric] {
		if err := p.ops.AddRoute(ctx, p.guardRoute(ingressGuardFloorMetric)); err != nil {
			if !p.routeExists(ctx, p.guardRoute(ingressGuardFloorMetric)) {
				return errors.New("cannot install Hestia ingress guard")
			}
		}
	}
	return nil
}

// Preflight rejects unowned routes, colliding same-priority rules, or unavailable LAN ingress.
func (p IngressPolicy) Preflight(ctx context.Context) error {
	if p.ops == nil || p.table < ingressTableMinimum || p.table > ingressTableMaximum ||
		p.mark < 0x0ffff000 || p.mark > 0x0fffffff || !ingressInterfacePattern.MatchString(p.ingress) ||
		!ingressDevicePattern.MatchString(p.tunnel) {
		return errors.New("invalid Keenetic ingress policy identity")
	}
	linksUp, err := p.ops.LinkUp(ctx, p.ingress)
	if err != nil || !linksUp {
		return errors.New("LAN ingress interface is unavailable")
	}
	routes, err := p.ops.Routes(ctx, p.table)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress table")
	}
	_, err = p.inspectRoutes(routes)
	if err != nil {
		return err
	}
	rules, err := p.ops.Rules(ctx)
	if err != nil {
		return errors.New("cannot inspect IPv4 policy rules")
	}
	for _, rule := range rules {
		if rule.Table == p.table && !p.isOwnedRule(rule) {
			return errors.New("Hestia ingress table is referenced by an unowned rule")
		}
		if rule.Priority != ingressRoutePriority && rule.Priority != ingressBlockPriority {
			continue
		}
		if p.isOwnedRule(rule) || !p.selectorMayMatch(rule) {
			continue
		}
		return errors.New("Hestia ingress priority collides with an unowned rule")
	}
	return nil
}

// ActivateIPv4 adds a ready TUN route behind the floor guard, then removes the active blocking route.
func (p IngressPolicy) ActivateIPv4(ctx context.Context) error {
	if err := p.Preflight(ctx); err != nil {
		return err
	}
	linksUp, err := p.ops.LinkUp(ctx, p.tunnel)
	if err != nil {
		return errors.New("cannot inspect Hestia TUN interface")
	}
	if !linksUp {
		if err := p.InstallGuard(ctx); err != nil {
			return err
		}
		return errors.New("Hestia TUN interface is not ready")
	}
	routes, err := p.ops.Routes(ctx, p.table)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress table")
	}
	state, err := p.inspectRoutes(routes)
	if err != nil {
		return err
	}
	active := p.tunnelRoute()
	if !state[ingressGuardFloorMetric] && state[ingressRouteMetric] {
		fallback := p.guardRoute(ingressGuardMetric)
		if !state[ingressGuardMetric] {
			if err := p.ops.AddRoute(ctx, fallback); err != nil && !p.routeExists(ctx, fallback) {
				if guardErr := p.InstallGuard(ctx); guardErr != nil {
					return guardErr
				}
				return errors.New("cannot restore Hestia high-metric fallback guard")
			}
		}
		if err := p.ensureRule(ctx, p.blockRule); err != nil {
			return err
		}
		if err := p.ensureRule(ctx, p.ipv6Rule); err != nil {
			return err
		}
		return p.ensureRule(ctx, p.lookupRule)
	}
	if err := p.InstallGuard(ctx); err != nil {
		return err
	}
	if err := p.ops.AddRoute(ctx, active); err != nil && !p.routeExists(ctx, active) {
		return errors.New("cannot install Hestia TUN route")
	}
	guard := p.guardRoute(ingressGuardMetric)
	if err := p.ops.AddRoute(ctx, guard); err != nil && !p.routeExists(ctx, guard) {
		return errors.New("cannot install Hestia high-metric fallback guard")
	}
	if err := p.deleteIfPresent(ctx, p.guardRoute(ingressGuardFloorMetric)); err != nil {
		return err
	}
	return nil
}

// DeactivateIPv4 installs a lowest-metric unreachable default before deleting any active TUN route.
func (p IngressPolicy) DeactivateIPv4(ctx context.Context) error {
	if err := p.InstallGuard(ctx); err != nil {
		return err
	}
	linksUp, err := p.ops.LinkUp(ctx, p.tunnel)
	if err != nil {
		return errors.New("cannot inspect Hestia TUN interface")
	}
	if !linksUp {
		// The floor guard makes the link-down route unreachable until the TUN reader is ready.
		return nil
	}
	if err := p.deleteIfPresent(ctx, p.tunnelRoute()); err != nil {
		return err
	}
	return p.deleteIfPresent(ctx, p.guardRoute(ingressGuardMetric))
}

// Remove removes only exact Hestia routes/rules after the caller confirms no Keenetic policy still selects this ingress.
func (p IngressPolicy) Remove(ctx context.Context) error {
	if p.ops == nil || p.table < ingressTableMinimum || p.table > ingressTableMaximum ||
		p.mark < 0x0ffff000 || p.mark > 0x0fffffff || !ingressInterfacePattern.MatchString(p.ingress) ||
		!ingressDevicePattern.MatchString(p.tunnel) {
		return errors.New("invalid Keenetic ingress policy identity")
	}
	routes, err := p.ops.Routes(ctx, p.table)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress table before removal")
	}
	state, err := p.inspectRoutes(routes)
	if err != nil {
		return err
	}
	rules, err := p.ops.Rules(ctx)
	if err != nil {
		return errors.New("cannot inspect IP policy rules before removal")
	}
	for _, rule := range rules {
		if rule.Table == p.table && !p.isOwnedRule(rule) {
			return errors.New("Hestia ingress table is referenced by an unowned rule")
		}
		if (rule.Priority == ingressRoutePriority || rule.Priority == ingressBlockPriority) &&
			!p.isOwnedRule(rule) && p.selectorMayMatch(rule) {
			return errors.New("Hestia ingress priority collides with an unowned rule")
		}
	}
	if !state[ingressGuardFloorMetric] {
		guard := p.guardRoute(ingressGuardFloorMetric)
		if err := p.ops.AddRoute(ctx, guard); err != nil && !p.routeExists(ctx, guard) {
			return errors.New("cannot install Hestia ingress guard before removal")
		}
	}
	for _, route := range []ingressRoute{p.tunnelRoute(), p.guardRoute(ingressGuardMetric)} {
		if err := p.deleteIfPresent(ctx, route); err != nil {
			return err
		}
	}
	for _, rule := range []ingressRule{p.ipv6Rule, p.blockRule, p.lookupRule} {
		if err := p.deleteRuleIfPresent(ctx, rule); err != nil {
			return err
		}
	}
	return p.deleteIfPresent(ctx, p.guardRoute(ingressGuardFloorMetric))
}

// ensureRule installs one exact rule and adopts it only after a fresh kernel dump proves full identity.
func (p IngressPolicy) ensureRule(ctx context.Context, wanted ingressRule) error {
	rules, err := p.ops.Rules(ctx)
	if err != nil {
		return errors.New("cannot inspect IPv4 policy rules")
	}
	for _, rule := range rules {
		if rule.Priority == wanted.Priority && p.isOwnedRuleFor(rule, wanted) {
			return nil
		}
	}
	if err := p.ops.AddRule(ctx, wanted); err != nil {
		if p.ruleExists(ctx, wanted) {
			return nil
		}
		return errors.New("cannot install Hestia ingress policy rule")
	}
	return nil
}

// inspectRoutes accepts only the Hestia guard routes and the exact OpkgTun default route in the owned table.
func (p IngressPolicy) inspectRoutes(routes []ingressRoute) (map[uint32]bool, error) {
	state := map[uint32]bool{}
	for _, route := range routes {
		linkDownTunnelRoute := route.Flags == ingressRouteFlagLinkDown && route.Type == ingressUnicast &&
			route.Device == p.tunnel && route.Metric == ingressRouteMetric
		if route.Table != p.table || route.PrefixBits != 0 || route.SourcePrefixBits != 0 || route.TOS != 0 ||
			route.Scope != 0 || route.Protocol != ingressRouteProtocol || (route.Flags != 0 && !linkDownTunnelRoute) ||
			route.HasGateway || route.HasOtherAttributes {
			return nil, errors.New("Hestia ingress table contains an unowned route")
		}
		owned := route.Type == ingressUnreachable && route.Device == "" &&
			(route.Metric == ingressGuardFloorMetric || route.Metric == ingressGuardMetric)
		if route.Type == ingressUnicast && route.Device == p.tunnel && route.Metric == ingressRouteMetric {
			owned = true
		}
		if !owned || state[route.Metric] {
			return nil, errors.New("Hestia ingress table contains an unowned route")
		}
		state[route.Metric] = true
	}
	return state, nil
}

// selectorMayMatch reports whether an existing rule at a reserved priority can match the target mark and bridge.
func (p IngressPolicy) selectorMayMatch(rule ingressRule) bool {
	if rule.Family != ingressIPv4Family && rule.Family != ingressIPv6Family {
		return false
	}
	if rule.Input != "" && rule.Input != p.ingress {
		return false
	}
	if rule.HasMark && ((rule.Mark^p.mark)&rule.Mask) != 0 {
		return false
	}
	return true
}

// isOwnedRule confirms a same-priority rule is exactly one of this adapter's lookup or terminal rules.
func (p IngressPolicy) isOwnedRule(rule ingressRule) bool {
	return p.isOwnedRuleFor(rule, p.lookupRule) || p.isOwnedRuleFor(rule, p.blockRule) || p.isOwnedRuleFor(rule, p.ipv6Rule)
}

// isOwnedRuleFor requires a persisted Hestia ownership record and an exact match of every routing selector and action field.
func (p IngressPolicy) isOwnedRuleFor(actual, expected ingressRule) bool {
	return actual.Owned && sameIngressRuleIdentity(actual, expected)
}

// sameIngressRuleIdentity compares every kernel-visible selector and action field without asserting ownership.
func sameIngressRuleIdentity(actual, expected ingressRule) bool {
	return actual.Family == expected.Family && actual.Priority == expected.Priority && actual.Protocol == expected.Protocol && actual.Mark == expected.Mark &&
		actual.Mask == expected.Mask && actual.Table == expected.Table && actual.Action == expected.Action &&
		actual.Input == expected.Input && actual.SourcePrefixBits == expected.SourcePrefixBits &&
		actual.DestPrefixBits == expected.DestPrefixBits && actual.TOS == expected.TOS && actual.Flags == expected.Flags &&
		actual.HasOtherSelectors == expected.HasOtherSelectors && actual.HasMark == expected.HasMark
}

// guardRoute returns the exact unreachable default route owned by this policy at the requested metric.
func (p IngressPolicy) guardRoute(metric uint32) ingressRoute {
	return ingressRoute{Table: p.table, PrefixBits: 0, Type: ingressUnreachable, Protocol: ingressRouteProtocol, Metric: metric}
}

// tunnelRoute returns the exact IPv4 default route from this policy table into the named OpkgTun device.
func (p IngressPolicy) tunnelRoute() ingressRoute {
	return ingressRoute{Table: p.table, PrefixBits: 0, Type: ingressUnicast, Protocol: ingressRouteProtocol, Metric: ingressRouteMetric, Device: p.tunnel}
}

// routeExists checks one exact route against a fresh bounded table inventory.
func (p IngressPolicy) routeExists(ctx context.Context, wanted ingressRoute) bool {
	exists, err := p.findRoute(ctx, wanted)
	return err == nil && exists
}

// findRoute distinguishes an absent route from a failed or incomplete kernel inventory.
func (p IngressPolicy) findRoute(ctx context.Context, wanted ingressRoute) (bool, error) {
	routes, err := p.ops.Routes(ctx, p.table)
	if err != nil {
		return false, err
	}
	for _, route := range routes {
		if route == wanted {
			return true, nil
		}
	}
	return false, nil
}

// ruleExists checks one exact rule against a fresh RPDB inventory.
func (p IngressPolicy) ruleExists(ctx context.Context, wanted ingressRule) bool {
	rules, err := p.ops.Rules(ctx)
	if err != nil {
		return false
	}
	for _, rule := range rules {
		if p.isOwnedRuleFor(rule, wanted) {
			return true
		}
	}
	return false
}

// deleteRuleIfPresent removes one exact owned rule and tolerates absence only after a fresh RPDB dump confirms it.
func (p IngressPolicy) deleteRuleIfPresent(ctx context.Context, wanted ingressRule) error {
	rules, err := p.ops.Rules(ctx)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress rule before removal")
	}
	var ownedRule ingressRule
	for _, rule := range rules {
		if p.isOwnedRuleFor(rule, wanted) {
			ownedRule = rule
			break
		}
	}
	if !ownedRule.Owned {
		return nil
	}
	if err := p.ops.DeleteRule(ctx, ownedRule); err != nil {
		rules, inspectErr := p.ops.Rules(ctx)
		if inspectErr != nil {
			return errors.New("cannot verify Hestia ingress rule removal")
		}
		for _, rule := range rules {
			if sameIngressRuleIdentity(rule, wanted) {
				return errors.New("cannot remove Hestia ingress rule; guarded state must be retained")
			}
		}
	}
	return nil
}

// deleteIfPresent deletes an exact owned route and tolerates absence only after a fresh inventory confirms it.
func (p IngressPolicy) deleteIfPresent(ctx context.Context, wanted ingressRoute) error {
	exists, err := p.findRoute(ctx, wanted)
	if err != nil {
		return errors.New("cannot inspect Hestia ingress route before removal")
	}
	if !exists {
		return nil
	}
	if err := p.ops.DeleteRoute(ctx, wanted); err != nil {
		stillExists, inspectErr := p.findRoute(ctx, wanted)
		if inspectErr != nil || stillExists {
			return fmt.Errorf("cannot remove owned Hestia ingress route")
		}
	}
	return nil
}
