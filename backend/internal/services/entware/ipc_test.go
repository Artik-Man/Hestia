//go:build linux

package entware

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
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

// TestBootServicesRecoverConnectorsBeforeRouting verifies committed AWG runtimes are restored before router and controller startup.
func TestBootServicesRecoverConnectorsBeforeRouting(t *testing.T) {
	var events []string
	recoverBindings := func(context.Context) error {
		events = append(events, "recover-bindings")
		return nil
	}
	startService := func(_ context.Context, service services.Service) error {
		switch service.Kind {
		case services.Router:
			events = append(events, "router")
		case services.Controller:
			events = append(events, "controller")
		default:
			t.Errorf("unexpected boot service kind: %d", service.Kind)
		}
		return nil
	}
	if err := startBootServices(context.Background(), recoverBindings, startService); err != nil {
		t.Fatal(err)
	}
	want := []string{"recover-bindings", "router", "controller"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("boot events = %v, want %v", events, want)
	}
}

// TestBootServicesStopWhenConnectorRecoveryFails prevents routing services from starting with an un-restored committed connector generation.
func TestBootServicesStopWhenConnectorRecoveryFails(t *testing.T) {
	var starts int
	recoverBindings := func(context.Context) error { return errors.New("fixture recovery failure") }
	startService := func(context.Context, services.Service) error {
		starts++
		return nil
	}
	if err := startBootServices(context.Background(), recoverBindings, startService); err == nil || starts != 0 {
		t.Fatalf("boot continued after connector recovery failure: err=%v starts=%d", err, starts)
	}
}

// TestBindingRecoveryErrorPreservesStderr keeps the cause of a failed boot recovery in supervisor diagnostics.
func TestBindingRecoveryErrorPreservesStderr(t *testing.T) {
	err := bindingRecoveryError(&exec.ExitError{Stderr: []byte("profile recovery failed\n")})
	if got, want := err.Error(), "binding recovery failed: profile recovery failed"; got != want {
		t.Fatalf("bindingRecoveryError() = %q, want %q", got, want)
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
