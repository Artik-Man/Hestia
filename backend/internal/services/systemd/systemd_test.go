package systemd

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/services"
)

// TestBatchMappingPreservesOrder checks one platform invocation and caller ordering, including legacy AWG IDs.
func TestBatchMappingPreservesOrder(t *testing.T) {
	var calls [][]string
	manager := Manager{Run: func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	batch := []services.Service{{Kind: services.Controller}, {Kind: services.Router}, {Kind: services.AWG, Instance: "awg-first"}}
	if err := manager.Stop(context.Background(), batch...); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"/usr/bin/systemctl", "stop", "hestia.service", "hestia-sing-box.service", "hestia-awg@awg-first.service"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

// TestInvalidIdentityRejectsWholeBatch ensures malformed input cannot execute even earlier valid items.
func TestInvalidIdentityRejectsWholeBatch(t *testing.T) {
	invalid := []services.Service{{}, {Kind: 255}, {Kind: services.AWG, Instance: "../../other"}, {Kind: services.AWG}, {Kind: services.Router, Instance: "unexpected"}}
	manager := Manager{Run: func(context.Context, string, ...string) error {
		t.Fatal("invalid batch reached command runner")
		return nil
	}}
	for _, service := range invalid {
		if err := manager.Start(context.Background(), services.Service{Kind: services.Controller}, service); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid service %v returned %v", service, err)
		}
	}
	if err := manager.Stop(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty batch returned %v", err)
	}
}

// TestStatusDistinguishesInactiveAndUnknown verifies only code 3 confirms inactivity and original errors survive.
func TestStatusDistinguishesInactiveAndUnknown(t *testing.T) {
	inactive := exec.Command("sh", "-c", "exit 3").Run()
	unknown := exec.Command("sh", "-c", "exit 4").Run()
	for _, test := range []struct {
		name  string
		err   error
		state services.State
	}{{"active", nil, services.Active}, {"inactive", inactive, services.Inactive}, {"unknown", unknown, services.Unknown}} {
		t.Run(test.name, func(t *testing.T) {
			manager := Manager{Run: func(_ context.Context, name string, args ...string) error {
				if name != "/usr/bin/systemctl" || !reflect.DeepEqual(args, []string{"is-active", "--quiet", "hestia-sing-box.service"}) {
					t.Fatalf("unexpected status command: %s %v", name, args)
				}
				return test.err
			}}
			state, err := manager.Status(context.Background(), services.Service{Kind: services.Router})
			if state != test.state || err != test.err {
				t.Fatalf("status = %v, %v; want %v, %v", state, err, test.state, test.err)
			}
		})
	}
}

// TestCancellationAndDeadline keeps platform operations bounded and never interprets cancellation as inactive.
func TestCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := Manager{Run: func(ctx context.Context, _ string, _ ...string) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 20*time.Second {
			t.Fatal("command lacks the 20-second upper bound")
		}
		return ctx.Err()
	}}
	state, err := manager.Status(ctx, services.Service{Kind: services.Router})
	if state != services.Unknown || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled status = %v, %v", state, err)
	}
}

// TestBatchFailureIsReturnedWithoutRetry leaves recovery of a possibly partially executed operation to its coordinator.
func TestBatchFailureIsReturnedWithoutRetry(t *testing.T) {
	failure := errors.New("partial operation")
	calls := 0
	manager := Manager{Run: func(context.Context, string, ...string) error {
		calls++
		return failure
	}}
	err := manager.Start(context.Background(), services.Service{Kind: services.Router}, services.Service{Kind: services.Controller})
	if !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("batch returned %v after %d calls", err, calls)
	}
}
