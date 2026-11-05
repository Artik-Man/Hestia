package dnsresolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

type splitWarmRoutes struct {
	testRoutes
	fi, ru    Upstream
	fiEnabled atomic.Bool
}

// Allowed selects FI for the restricted name and permits RU fallback only for the shared name.
func (s *splitWarmRoutes) Allowed(_ context.Context, name string) ([]Upstream, error) {
	var paths []Upstream
	if s.fiEnabled.Load() {
		paths = append(paths, s.fi)
	}
	if name == "cdn.example" {
		paths = append(paths, s.ru)
	}
	return paths, nil
}

// TestSplitWarmRepeatedRevocation serves the latest RU address from cache after each FI ban.
func TestSplitWarmRepeatedRevocation(t *testing.T) {
	store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.Threshold = 2 })
	policy, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		routes := &splitWarmRoutes{fi: Upstream{"fi", "fi-resolver"}, ru: Upstream{"ru", "ru-resolver"}}
		routes.fiEnabled.Store(true)
		var calls, ruCalls, fiCalls atomic.Int32
		routes.send = func(_ context.Context, up Upstream, packet []byte) ([]byte, error) {
			calls.Add(1)
			if up == routes.fi {
				fiCalls.Add(1)
				return fixtureAnswer(packet, dnsmessage.RCodeSuccess, 100, 22)
			}
			return fixtureAnswer(packet, dnsmessage.RCodeSuccess, 20, byte(1+10*ruCalls.Add(1)))
		}
		r := New(store, routes, "")
		testQuery(t, r, "cdn.example")
		synctest.Wait()
		checkCached := func(ip byte, ttl uint32) {
			t.Helper()
			before := calls.Load()
			m := testQuery(t, r, "cdn.example")
			synctest.Wait()
			if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, ip} || m.Answers[0].Header.TTL != ttl || calls.Load() != before {
				t.Fatalf("expected cached .%d TTL %d, got %v, upstream calls %d -> %d", ip, ttl, m, before, calls.Load())
			}
		}
		checkCached(22, 100)
		if m := testQuery(t, r, "fi-only.example"); len(m.Answers) != 1 {
			t.Fatal(m)
		}
		for cycle := 1; cycle <= 2; cycle++ {
			time.Sleep(18 * time.Second)
			var workers sync.WaitGroup
			r.schedule(context.Background(), policy.Policy, &workers)
			workers.Wait()
			checkCached(22, uint32(100-18*cycle))
			routes.fiEnabled.Store(false)
			checkCached(byte(1+10*(cycle+1)), 20)
			before := calls.Load()
			if m := testQuery(t, r, "fi-only.example"); m.RCode != dnsmessage.RCodeServerFailure || len(m.Answers) != 0 || calls.Load() != before {
				t.Fatalf("FI-only lookup during ban %d: %v, upstream calls %d -> %d", cycle, m, before, calls.Load())
			}
			routes.fiEnabled.Store(true)
		}
		// At t=90s both paths are due. Only RU may be refreshed while FI is banned.
		routes.fiEnabled.Store(false)
		beforeFI, beforeRU := fiCalls.Load(), ruCalls.Load()
		time.Sleep(54 * time.Second)
		var workers sync.WaitGroup
		r.schedule(context.Background(), policy.Policy, &workers)
		workers.Wait()
		if fiCalls.Load() != beforeFI || ruCalls.Load() != beforeRU+1 {
			t.Fatalf("scheduled requests during FI ban: FI %d -> %d, RU %d -> %d", beforeFI, fiCalls.Load(), beforeRU, ruCalls.Load())
		}

	})
}
