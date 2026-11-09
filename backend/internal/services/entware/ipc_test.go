//go:build linux

package entware

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/services"
)

// TestPublicErrorIncludesOnlyFixedServiceRole ensures public errors expose the role name without IPC internals.
func TestPublicErrorIncludesOnlyFixedServiceRole(t *testing.T) {
	if got := publicError(errors.New("private command output"), serviceRole(services.Router)); got != "managed service operation failed: router" {
		t.Fatalf("publicError() = %q, want fixed router category", got)
	}
	if got := publicError(ErrUnavailable, serviceRole(services.Controller)); got != "managed service role unavailable: controller" {
		t.Fatalf("publicError() = %q, want fixed controller category", got)
	}
}

// TestRouterIPCStartRequiresIngressReadiness prevents root IPC callers from bypassing the supervisor startup gate.
func TestRouterIPCStartRequiresIngressReadiness(t *testing.T) {
	table := processTable{}
	table.requireIngressGate()
	result := dispatch(context.Background(), &table, request{
		Operation: "start",
		Services:  []services.Service{{Kind: services.Router}},
	})
	if result.Error != "managed service operation failed: router" || len(table.entries) != 0 {
		t.Fatalf("router IPC start bypassed ingress readiness: result=%#v entries=%#v", result, table.entries)
	}
}

// TestIngressReconcileIPCInvokesSerializedLifecycle proves NDM callbacks reach the supervisor reconciler.
func TestIngressReconcileIPCInvokesSerializedLifecycle(t *testing.T) {
	table := processTable{}
	called := false
	table.setIngressSync(func(ctx context.Context, forceGuard bool) error {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 500*time.Millisecond || forceGuard {
			t.Errorf("ingress IPC did not preserve its bounded client deadline: deadline=%v ok=%t forceGuard=%t", deadline, ok, forceGuard)
		}
		return nil
	})
	result := dispatch(context.Background(), &table, request{Operation: "reconcile-ingress", TimeoutMillis: 500})
	if result.Error != "" || !called {
		t.Fatalf("ingress reconcile IPC did not invoke lifecycle callback: result=%#v called=%t", result, called)
	}
}

// TestIngressReconcileWaitCanBeCanceled keeps the hook deadline effective while another reconciliation holds the slot.
func TestIngressReconcileWaitCanBeCanceled(t *testing.T) {
	table := processTable{}
	entered := make(chan struct{})
	table.setIngressSync(func(ctx context.Context, _ bool) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- table.reconcileIngress(firstCtx, false) }()
	<-entered
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	cancelSecond()
	if err := table.reconcileIngress(secondCtx, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting reconcile ignored canceled context: %v", err)
	}
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("active reconcile did not observe cancellation: %v", err)
	}
}
