package platformhelper

import (
	"context"
	"io"
	"testing"
)

// TestInvalidOperationsRejectBeforePrivilegeBoundary verifies no arbitrary mode reaches sudo.
func TestInvalidOperationsRejectBeforePrivilegeBoundary(t *testing.T) {
	for _, mode := range []Mode{"", "-n", "-apply-binding;id", "/bin/sh"} {
		if (Installed{}).Execute(context.Background(), mode, nil, io.Discard, Caller) == nil {
			t.Fatalf("accepted %q", mode)
		}
	}
	if (Installed{}).Execute(context.Background(), "-awg-list", nil, io.Discard, Cancellation(99)) == nil {
		t.Fatal("invalid cancellation accepted")
	}
}

// TestCancelledTransactionNeverStarts ensures a disconnected request cannot begin a new root transaction.
func TestCancelledTransactionNeverStarts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (Installed{}).Execute(ctx, "-apply-binding", nil, io.Discard, Transaction); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}
