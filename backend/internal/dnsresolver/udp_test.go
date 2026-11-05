package dnsresolver

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

// TestUDPAttemptIdentity exercises the actual request entry point including cache-independent demand and client counters.
func TestUDPAttemptIdentity(t *testing.T) {
	store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.Threshold = 1 })
	r := New(store, &testRoutes{}, "")
	first := netip.MustParseAddrPort("192.0.2.1:53000")
	for _, tc := range []struct {
		peer netip.AddrPort
		id   uint16
		name string
		kind dnsmessage.Type
	}{
		{first, 1, "a.example", dnsmessage.TypeA}, {first, 1, "A.example", dnsmessage.TypeA}, {first, 1, "a.example", dnsmessage.TypeA},
		{first, 2, "a.example", dnsmessage.TypeA}, {netip.MustParseAddrPort("192.0.2.1:53001"), 1, "a.example", dnsmessage.TypeA},
		{netip.MustParseAddrPort("192.0.2.2:53000"), 1, "a.example", dnsmessage.TypeA}, {first, 1, "a.example", dnsmessage.TypeAAAA}, {first, 1, "b.example", dnsmessage.TypeA},
	} {
		p, err := buildQuery(tc.name, tc.kind)
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(p, tc.id)
		if _, err := r.ResolveUDP(context.Background(), tc.peer, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.ResolveUDP(context.Background(), first, []byte{1}); err == nil {
		t.Fatal("malformed packet accepted")
	}
	p, _ := buildQuery("b.example", dnsmessage.TypeA)
	if _, err := r.Resolve(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := r.ClientUDPStats(); got.Attempts != 8 || got.RetriedAttempts != 2 {
		t.Fatal(got)
	}
	if len(r.demand["a.example"]) != 5 || len(r.demand["b.example"]) != 2 {
		t.Fatal(r.demand)
	}
}

// TestUDPAttemptExpiry checks both sides of the configured observation window, including the exclusive lower bound.
func TestUDPAttemptExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var tracker udpTracker
		k := udpKey{id: 1}
		if tracker.record(k, time.Hour) {
			t.Fatal("first classified as retry")
		}
		time.Sleep(time.Hour - time.Nanosecond)
		if !tracker.record(k, time.Hour) {
			t.Fatal("retry missed")
		}
		time.Sleep(time.Nanosecond)
		if tracker.record(k, time.Hour) {
			t.Fatal("expired transaction retained")
		}
	})
}

// TestUDPAttemptClass verifies a CHAOS question sharing the same ID and name cannot suppress an IN visit.
func TestUDPAttemptClass(t *testing.T) {
	store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.Threshold = 1 })
	r := New(store, &testRoutes{}, "")
	peer := netip.MustParseAddrPort("192.0.2.1:53000")
	packet, _ := buildQuery("a.example", dnsmessage.TypeA)
	binary.BigEndian.PutUint16(packet[len(packet)-2:], uint16(dnsmessage.ClassCHAOS))
	if _, err := r.ResolveUDP(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(packet[len(packet)-2:], uint16(dnsmessage.ClassINET))
	if _, err := r.ResolveUDP(context.Background(), peer, packet); err != nil {
		t.Fatal(err)
	}
	if got := r.ClientUDPStats(); got.Attempts != 2 || got.RetriedAttempts != 0 || len(r.demand["a.example"]) != 1 {
		t.Fatalf("%+v %v", got, r.demand)
	}
}

// TestUDPAttemptSaturation verifies an untracked transaction cannot displace live identities or contribute spurious demand.
func TestUDPAttemptSaturation(t *testing.T) {
	var tracker udpTracker
	for i := range maxUDPTransactions {
		if tracker.record(udpKey{id: uint16(i)}, time.Hour) {
			t.Fatalf("early saturation at %d", i)
		}
	}
	if !tracker.record(udpKey{id: maxUDPTransactions}, time.Hour) || !tracker.record(udpKey{id: 0}, time.Hour) {
		t.Fatal("saturation manufactured demand")
	}
	if len(tracker.entries) != maxUDPTransactions || tracker.stats.UnclassifiedAttempts != 1 || tracker.stats.RetriedAttempts != 1 {
		t.Fatal(tracker.stats)
	}
}

// TestUDPIdleWindowChange verifies that a scheduler tick forgets expired identities while preserving lifetime totals.
func TestUDPIdleWindowChange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const name = "window.example"
		store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.WindowHours = 8; p.Settings.Threshold = 1 })
		r := New(store, &testRoutes{}, "")
		ctx, cancel := context.WithCancel(t.Context())
		go r.Run(ctx, time.Hour)
		synctest.Wait()
		defer func() { cancel(); synctest.Wait() }()
		query, err := buildQuery(name, dnsmessage.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		peer := netip.MustParseAddrPort("192.0.2.1:53000")
		send := func() {
			t.Helper()
			if _, err := r.ResolveUDP(ctx, peer, query); err != nil {
				t.Fatal(err)
			}
		}
		setWindow := func(hours int) {
			t.Helper()
			snap, err := store.Read()
			if err != nil {
				t.Fatal(err)
			}
			snap.Policy.Settings.WindowHours = hours
			if _, err := store.Apply(snap.Revision, snap.Policy); err != nil {
				t.Fatal(err)
			}
		}
		send()
		send()
		setWindow(1)
		time.Sleep(time.Hour)
		synctest.Wait()
		// No Observations or packets under the shorter window; only the idle scheduler could have expired the key.
		setWindow(8)
		send()
		assertAutomatic(t, r, name, 1)
		if got := r.ClientUDPStats(); got.Attempts != 3 || got.RetriedAttempts != 1 || got.UnclassifiedAttempts != 0 {
			t.Fatal(got)
		}
	})
}
