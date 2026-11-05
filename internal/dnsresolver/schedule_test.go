package dnsresolver

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

// startScheduledResolver runs the real worker against a private policy and an upstream whose A address changes on every request.
func startScheduledResolver(t *testing.T, name string, ttl uint32, threshold, intervalMinutes int, tick time.Duration) (*Resolver, *atomic.Int32) {
	t.Helper()
	store := testPolicy(t, func(p *dnspolicy.Policy) {
		p.Settings.Threshold = threshold
		p.Settings.WindowHours = 1
		p.Settings.IntervalMinutes = intervalMinutes
	})
	count := new(atomic.Int32)
	up := Upstream{"test-exit", "test-resolver"}
	routes := &testRoutes{allowed: []Upstream{up}}
	routes.send = func(_ context.Context, got Upstream, packet []byte) ([]byte, error) {
		var wire dnsmessage.Message
		if err := wire.Unpack(packet); err != nil {
			return nil, err
		}
		if got != up || len(wire.Questions) != 1 || wire.Questions[0].Type != dnsmessage.TypeA || wire.Questions[0].Name.String() != name+"." {
			t.Errorf("unexpected upstream context or question: %+v %+v", got, wire.Questions)
		}
		return fixtureAnswer(packet, dnsmessage.RCodeSuccess, ttl, byte(count.Add(1)))
	}
	r := New(store, routes, "")
	ctx, cancel := context.WithCancel(context.Background())
	go r.Run(ctx, tick)
	synctest.Wait()
	t.Cleanup(func() { cancel(); synctest.Wait() })
	return r, count
}

// advanceSchedule advances only the synctest clock and waits for any due worker exchanges to finish.
func advanceSchedule(elapsed time.Duration) {
	time.Sleep(elapsed)
	synctest.Wait()
}

// assertAutomatic verifies published demand for the expected domain together with the current persisted policy revision.
func assertAutomatic(t *testing.T, r *Resolver, name string, requests int) {
	t.Helper()
	snap, err := r.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	_, revision, automatic, err := r.Observations()
	if err != nil || revision != snap.Revision {
		t.Fatalf("observations revision %d, want %d: %v", revision, snap.Revision, err)
	}
	if requests == 0 && len(automatic) != 0 || requests > 0 && (len(automatic) != 1 || automatic[name] != requests) {
		t.Fatalf("at %v: automatic=%v, want %s with %d requests (zero means absent)", time.Now(), automatic, name, requests)
	}
}

// replaceExclusions updates only automatic exclusions in the real durable store, without creating a client visit.
func replaceExclusions(t *testing.T, store dnspolicy.Store, names []string) {
	t.Helper()
	snap, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	snap.Policy.Exclusions = names
	if _, err := store.Apply(snap.Revision, snap.Policy); err != nil {
		t.Fatal(err)
	}
}

// TestAutomaticExclusionResumeAndWindowExpiry exercises real scheduled sends while requests enter and leave the rolling window.
func TestAutomaticExclusionResumeAndWindowExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const name = "automatic.example"
		r, calls := startScheduledResolver(t, name, 7200, 2, 10, time.Minute)

		testQuery(t, r, name)
		advanceSchedule(10 * time.Minute)
		assertAutomatic(t, r, name, 0)
		if calls.Load() != 1 {
			t.Fatal("N−1 client queries triggered a background exchange")
		}

		testQuery(t, r, name) // Cached second visit at minute 10.
		assertAutomatic(t, r, name, 2)
		advanceSchedule(time.Minute)
		if calls.Load() != 2 {
			t.Fatal("eligible domain did not refresh at the next worker tick")
		}

		replaceExclusions(t, r.store, []string{name})
		advanceSchedule(28 * time.Minute) // More than two Y intervals without a client query.
		assertAutomatic(t, r, name, 0)
		if calls.Load() != 2 {
			t.Fatalf("blacklisted auto-only name generated upstream traffic: %d", calls.Load())
		}

		replaceExclusions(t, r.store, []string{})
		advanceSchedule(time.Minute) // Minute 40; both original visits are still in X.
		assertAutomatic(t, r, name, 2)
		if calls.Load() != 3 {
			t.Fatalf("removing exclusion did not resume refresh without a client: %d", calls.Load())
		}

		advanceSchedule(19 * time.Minute)
		assertAutomatic(t, r, name, 2)
		if calls.Load() != 4 {
			t.Fatalf("expected exactly one scheduled exchange at minute 50, got %d total", calls.Load())
		}
		advanceSchedule(time.Minute) // At minute 60 the first visit expires exactly when the next refresh would be due.
		assertAutomatic(t, r, name, 0)
		replaceExclusions(t, r.store, []string{name})
		replaceExclusions(t, r.store, []string{})
		advanceSchedule(20 * time.Minute)
		assertAutomatic(t, r, name, 0)
		if calls.Load() != 4 {
			t.Fatalf("expired demand or removing exclusion below threshold resumed refresh: %d", calls.Load())
		}
	})
}

// TestScheduledRefreshUsesEarlierOfIntervalAndTTL checks the wire address after a proactive refresh of a still-valid record.
func TestScheduledRefreshUsesEarlierOfIntervalAndTTL(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		ttl                     uint32
		minutes                 int
		checkBefore, checkAfter time.Duration
	}{
		{name: "interval-first", ttl: 600, minutes: 1, checkBefore: 59 * time.Second, checkAfter: time.Minute},
		{name: "ttl-first", ttl: 20, minutes: 5, checkBefore: 17 * time.Second, checkAfter: 18 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const name = "rotation.example"
				r, calls := startScheduledResolver(t, name, tc.ttl, 1, tc.minutes, time.Second)
				first := testQuery(t, r, name)
				if len(first.Answers) != 1 || first.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 1} {
					t.Fatal("wrong first address")
				}
				advanceSchedule(tc.checkBefore)
				if calls.Load() != 1 {
					t.Fatal("worker refreshed too early")
				}
				advanceSchedule(tc.checkAfter - tc.checkBefore)
				if calls.Load() != 2 {
					t.Fatalf("expected a proactive refresh of a still-valid record, got %d upstream queries", calls.Load())
				}
				assertAutomatic(t, r, name, 1)
				next := testQuery(t, r, name)
				if len(next.Answers) != 1 || next.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 2} || calls.Load() != 2 {
					t.Fatalf("client did not get new address from cache: %+v, upstream requests %d", next.Answers, calls.Load())
				}
			})
		})
	}
}
