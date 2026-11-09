//go:build keenetic

package keeneticroute

import (
	"context"
	"errors"
	"fmt"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const managedOpkgTun = "OpkgTun0"

// IPPolicyReader supplies authenticated, typed Keenetic policy snapshots to the ingress reconciler.
type IPPolicyReader interface {
	ReadIPPolicies(context.Context) ([]keeneticrci.IPPolicy, error)
}

// IngressReconciler maps policies permitting the managed OpkgTun to Hestia route tables and fail-closed guards.
type IngressReconciler struct {
	reader  IPPolicyReader
	ops     ingressPolicyOps
	ingress string
	tunnel  string
}

// NewIngressReconciler creates a reader/route adapter pair for one fixed LAN bridge and managed OpkgTun.
func NewIngressReconciler(reader IPPolicyReader, ops ingressPolicyOps, ingress, tunnel string) (IngressReconciler, error) {
	if reader == nil || ops == nil || !ingressInterfacePattern.MatchString(ingress) ||
		tunnel != "opkgtun0" {
		return IngressReconciler{}, errors.New("invalid Keenetic ingress reconciler configuration")
	}
	return IngressReconciler{reader: reader, ops: ops, ingress: ingress, tunnel: tunnel}, nil
}

// Reconcile installs guards for every stable policy selecting Hestia before activating a ready TUN inbound.
func (r IngressReconciler) Reconcile(ctx context.Context, backendReady bool) error {
	if r.reader == nil || r.ops == nil {
		return errors.New("Keenetic ingress reconciler is unavailable")
	}
	policies, err := r.stablePolicies(ctx)
	if err != nil {
		return err
	}
	desired := make(map[uint32]IngressPolicy)
	for _, policy := range policies {
		if err := policy.Validate(); err != nil {
			return errors.New("Keenetic ingress policy identity is invalid")
		}
		if !containsInterface(policy.OpkgTunInterfaces, managedOpkgTun) {
			continue
		}
		table, err := IngressTableForMark(policy.Mark4)
		if err != nil {
			return err
		}
		adapter, err := NewIngressPolicy(r.ops, table, policy.Mark4, r.ingress, r.tunnel)
		if err != nil {
			return err
		}
		desired[policy.Mark4] = adapter
	}
	for _, adapter := range desired {
		if backendReady {
			err = adapter.ActivateIPv4(ctx)
		} else {
			err = adapter.DeactivateIPv4(ctx)
		}
		if err != nil {
			return fmt.Errorf("cannot reconcile Keenetic ingress policy: %w", err)
		}
	}
	return r.removeStale(ctx, desired)
}

// stablePolicies accepts a reconciliation snapshot only when two complete RCI reads agree on every routing identity.
func (r IngressReconciler) stablePolicies(ctx context.Context) ([]keeneticrci.IPPolicy, error) {
	first, err := r.reader.ReadIPPolicies(ctx)
	if err != nil {
		return nil, errors.New("cannot read Keenetic ingress policies")
	}
	second, err := r.reader.ReadIPPolicies(ctx)
	if err != nil {
		return nil, errors.New("cannot confirm Keenetic ingress policy snapshot")
	}
	if !samePolicies(first, second) {
		return nil, errors.New("Keenetic ingress policies changed during reconciliation")
	}
	return second, nil
}

// removeStale removes only route state whose Hestia marker is absent from the stable desired policy set.
func (r IngressReconciler) removeStale(ctx context.Context, desired map[uint32]IngressPolicy) error {
	rules, err := r.ops.Rules(ctx)
	if err != nil {
		return errors.New("cannot inspect ingress rules for stale Hestia state")
	}
	routes, err := r.ops.Routes(ctx, 0)
	if err != nil {
		return errors.New("cannot inspect ingress routes for stale Hestia state")
	}
	stale := make(map[uint32]IngressPolicy)
	for _, rule := range rules {
		if rule.Mark < 0x0ffff000 || rule.Mark > 0x0fffffff ||
			(rule.Priority != ingressRoutePriority && rule.Priority != ingressBlockPriority) ||
			rule.Input != r.ingress {
			continue
		}
		table, _ := IngressTableForMark(rule.Mark)
		adapter, err := NewIngressPolicy(r.ops, table, rule.Mark, r.ingress, r.tunnel)
		if err == nil && adapter.isOwnedRule(rule) && desired[rule.Mark].ops == nil {
			stale[rule.Mark] = adapter
		}
	}
	for _, route := range routes {
		if route.Protocol != ingressRouteProtocol || route.Table < ingressTableMinimum || route.Table > ingressTableMaximum {
			continue
		}
		mark := 0x0ffff000 + route.Table - ingressTableMinimum
		if desired[mark].ops != nil {
			continue
		}
		adapter, err := NewIngressPolicy(r.ops, route.Table, mark, r.ingress, r.tunnel)
		if err != nil {
			return errors.New("stale Hestia route identity is invalid")
		}
		stale[mark] = adapter
	}
	for _, adapter := range stale {
		if err := adapter.Remove(ctx); err != nil {
			return fmt.Errorf("cannot remove stale Hestia ingress state: %w", err)
		}
	}
	return nil
}

// containsInterface reports whether the sorted RCI interface list includes the exact managed NDM object.
func containsInterface(interfaces []string, wanted string) bool {
	for _, current := range interfaces {
		if current == wanted {
			return true
		}
	}
	return false
}

// samePolicies compares only routing identity and permitted OpkgTun values returned by the typed reader.
func samePolicies(left, right []keeneticrci.IPPolicy) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		a, b := left[index], right[index]
		if a.Key != b.Key || a.Table4 != b.Table4 || a.Mark4 != b.Mark4 ||
			len(a.OpkgTunInterfaces) != len(b.OpkgTunInterfaces) {
			return false
		}
		for item := range a.OpkgTunInterfaces {
			if a.OpkgTunInterfaces[item] != b.OpkgTunInterfaces[item] {
				return false
			}
		}
	}
	return true
}
