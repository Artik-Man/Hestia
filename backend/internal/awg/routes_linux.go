package awg

import (
	"context"
	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/network/linuxroute"
)

// RouteRunner retains the injected Linux command seam for installed composition.
type RouteRunner = linuxroute.RouteRunner

// ExecRouteRunner selects the installed Linux iproute2 adapter.
type ExecRouteRunner = linuxroute.ExecRouteRunner

// RoutePolicy combines a platform policy with immutable VPN allocation metadata.
type RoutePolicy struct {
	network.RoutePolicy
	mark, table, priority, device string
	markValue                     int
}

// NewRoutePolicy selects the legacy slot-zero Linux policy.
func NewRoutePolicy(runner RouteRunner) RoutePolicy {
	policy, _ := newSlotRoutePolicy(runner, 0)
	return policy
}

// newSlotRoutePolicy wires the Linux adapter to a validated VPN allocation.
func newSlotRoutePolicy(runner RouteRunner, slot int) (RoutePolicy, error) {
	policy, err := linuxroute.NewSlotPolicy(runner, slot)
	if err != nil {
		return RoutePolicy{}, err
	}
	return wrapRoutePolicy(policy), nil
}

// wrapRoutePolicy preserves allocation metadata while delegating semantic routing operations.
func wrapRoutePolicy(policy network.RoutePolicy) RoutePolicy {
	d := policy.Descriptor()
	return RoutePolicy{RoutePolicy: policy, mark: d.Mark, table: d.Table, priority: d.Priority, device: d.Device, markValue: d.MarkValue}
}

// verifyReadyPolicy verifies both-family guards and the active tunnel policy through its adapter.
func (p RoutePolicy) verifyReadyPolicy(ctx context.Context) error { return p.VerifyReadyPolicy(ctx) }
