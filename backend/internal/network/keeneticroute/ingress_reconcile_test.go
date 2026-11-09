//go:build keenetic

package keeneticroute

import (
	"context"
	"errors"
	"testing"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

type sequencePolicyReader struct {
	snapshots [][]keeneticrci.IPPolicy
	call      int
	err       error
}

// ReadIPPolicies returns the next configured snapshot for deterministic reconciliation tests.
func (reader *sequencePolicyReader) ReadIPPolicies(context.Context) ([]keeneticrci.IPPolicy, error) {
	if reader.err != nil {
		return nil, reader.err
	}
	if reader.call >= len(reader.snapshots) {
		return nil, errors.New("unexpected policy read")
	}
	snapshot := reader.snapshots[reader.call]
	reader.call++
	return snapshot, nil
}

// TestIngressReconcilerActivatesOnlyStableManagedPolicyKeepsExitGuard checks stable RCI selection and guarded TUN activation.
func TestIngressReconcilerActivatesOnlyStableManagedPolicyKeepsExitGuard(t *testing.T) {
	ctx := context.Background()
	selected := []keeneticrci.IPPolicy{{
		Key: "Policy0", Table4: 4104, Mark4: 0x0ffffab0,
		OpkgTunInterfaces: []string{managedOpkgTun},
	}}
	reader := &sequencePolicyReader{snapshots: [][]keeneticrci.IPPolicy{selected, selected, selected, selected}}
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	reconciler, err := NewIngressReconciler(reader, ops, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, false); err != nil {
		t.Fatal(err)
	}
	table, err := IngressTableForMark(selected[0].Mark4)
	if err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 1 || ops.routes[0] != (IngressPolicy{table: table}).guardRoute(ingressGuardFloorMetric) {
		t.Fatalf("unready router must retain a floor guard: %#v", ops.routes)
	}
	if len(ops.rules) != 3 {
		t.Fatalf("policy selection must install IPv6 block, IPv4 lookup and fallback rules: %#v", ops.rules)
	}

	ops.links["opkgtun0"] = true
	if err := reconciler.Reconcile(ctx, true); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 2 || ops.routes[0].Type != ingressUnicast || ops.routes[0].Device != "opkgtun0" {
		t.Fatalf("ready router must install the TUN default behind the fallback guard: %#v", ops.routes)
	}
	if ops.routes[1] != (IngressPolicy{table: table}).guardRoute(ingressGuardMetric) {
		t.Fatalf("active TUN route must retain the high-metric failure guard: %#v", ops.routes)
	}
}

// TestIngressReconcilerWaitsForStableRCIState ensures an in-flight policy edit cannot cause route mutation.
func TestIngressReconcilerWaitsForStableRCIState(t *testing.T) {
	selected := []keeneticrci.IPPolicy{{
		Key: "Policy0", Table4: 4104, Mark4: 0x0ffffab0,
		OpkgTunInterfaces: []string{managedOpkgTun},
	}}
	reader := &sequencePolicyReader{snapshots: [][]keeneticrci.IPPolicy{selected, {}}}
	ops := &memoryIngressOps{links: map[string]bool{"br0": true}}
	reconciler, err := NewIngressReconciler(reader, ops, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(context.Background(), true); err == nil {
		t.Fatal("unstable policy snapshot was accepted")
	}
	if len(ops.routes) != 0 || len(ops.rules) != 0 {
		t.Fatalf("unstable policy snapshot mutated route state: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
}

// TestIngressReconcilerRemovesStateOnlyAfterStablePolicyDetach checks stale owned rules/routes are removed after detachment.
func TestIngressReconcilerRemovesStateOnlyAfterStablePolicyDetach(t *testing.T) {
	ctx := context.Background()
	selected := []keeneticrci.IPPolicy{{
		Key: "Policy0", Table4: 4104, Mark4: 0x0ffffab0,
		OpkgTunInterfaces: []string{managedOpkgTun},
	}}
	detached := []keeneticrci.IPPolicy{{Key: "Policy0", Table4: 4104, Mark4: 0x0ffffab0}}
	reader := &sequencePolicyReader{snapshots: [][]keeneticrci.IPPolicy{selected, selected, detached, detached}}
	ops := &memoryIngressOps{links: map[string]bool{"br0": true, "opkgtun0": true}}
	reconciler, err := NewIngressReconciler(reader, ops, "br0", "opkgtun0")
	if err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := reconciler.Reconcile(ctx, false); err != nil {
		t.Fatal(err)
	}
	if len(ops.routes) != 0 || len(ops.rules) != 0 {
		t.Fatalf("stable policy detachment must remove Hestia state: routes=%#v rules=%#v", ops.routes, ops.rules)
	}
}
