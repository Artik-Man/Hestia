package trafficcapture

import (
	"context"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
)

// TestShutdownFlush verifies that stopping collection persists pending attribution and already-decoded messages.
func TestShutdownFlush(t *testing.T) {
	store, err := traffic.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(t.Context())
	stream := make(chan logMessage)
	done := make(chan struct{})
	lost := 0
	go func() { defer close(done); persistMessages(ctx, stream, store, &lost) }()
	received := time.Now().UTC()
	stream <- logMessage{"[11 0ms] inbound/tun[lan]: inbound connection to 192.0.2.1:443", received}
	cancel()
	stream <- logMessage{"[12 0ms] inbound/tun[lan]: inbound connection to 192.0.2.2:443", received}
	close(stream)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("collection did not drain")
	}
	page, err := store.Page(t.Context(), traffic.Query{Limit: 5})
	if err != nil || page.Total != 2 || page.Lost != 0 || lost != 0 {
		t.Fatalf("shutdown dropped pending events: %+v %v", page, err)
	}
}
