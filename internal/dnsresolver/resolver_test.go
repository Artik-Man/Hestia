package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

type testRoutes struct {
	mu      sync.Mutex
	allowed []Upstream
	send    func(context.Context, Upstream, []byte) ([]byte, error)
}

// Allowed supplies a snapshot of authorized fixture routes, independently mutable between exchanges.
func (p *testRoutes) Allowed(_ context.Context, _ string) ([]Upstream, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.allowed), nil
}

// Exchange dispatches the isolated test fixture's network behavior.
func (p *testRoutes) Exchange(ctx context.Context, up Upstream, packet []byte) ([]byte, error) {
	return p.send(ctx, up, packet)
}

// fixtureAnswer creates a matched A/AAAA address or an authoritative negative with a SOA TTL.
func fixtureAnswer(packet []byte, rcode dnsmessage.RCode, ttl uint32, ip byte) ([]byte, error) {
	q, err := parseQuestion(packet)
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.message.ID, Response: true, RecursionDesired: true, RecursionAvailable: true, RCode: rcode}, Questions: q.message.Questions}
	item := m.Questions[0]
	header := dnsmessage.ResourceHeader{Name: item.Name, Type: item.Type, Class: item.Class, TTL: ttl}
	if rcode == dnsmessage.RCodeSuccess {
		var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{192, 0, 2, ip}}
		if item.Type == dnsmessage.TypeAAAA {
			body = &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ip}}
		}
		m.Answers = []dnsmessage.Resource{{Header: header, Body: body}}
	} else if rcode == dnsmessage.RCodeNameError {
		header.Type = dnsmessage.TypeSOA
		m.Authorities = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.SOAResource{NS: item.Name, MBox: item.Name, MinTTL: ttl / 2}}}
	}
	return m.Pack()
}

// testPolicy saves a policy and returns an independently readable temporary store.
func testPolicy(t *testing.T, change func(*dnspolicy.Policy)) dnspolicy.Store {
	t.Helper()
	store := dnspolicy.Store{Path: filepath.Join(t.TempDir(), "policy.json")}
	initial, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(&initial.Policy)
	}
	if _, err = store.Apply(initial.Revision, initial.Policy); err != nil {
		t.Fatal(err)
	}
	return store
}

// testQuery resolves a recursive A question and decodes the client-visible message.
func testQuery(t *testing.T, r *Resolver, name string) dnsmessage.Message {
	t.Helper()
	q, err := buildQuery(name, dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(q, 1234)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, err := r.Resolve(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(p); err != nil {
		t.Fatal(err)
	}
	if m.ID != 1234 || m.Questions[0].Name.String() != name+"." {
		t.Fatalf("wrong client transaction or case: %+v", m)
	}
	return m
}

// TestParallelResolution verifies first positive wins, preserves resolver-specific cache and respects revocation.
func TestParallelResolution(t *testing.T) {
	ru := Upstream{"ru", "192.0.2.53"}
	fi := Upstream{"fi", "198.51.100.53"}
	routes := &testRoutes{allowed: []Upstream{ru, fi}}
	slow := make(chan struct{})
	defer close(slow)
	var calls atomic.Int32
	routes.send = func(ctx context.Context, up Upstream, p []byte) ([]byte, error) {
		calls.Add(1)
		if up == fi {
			select {
			case <-slow:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return fixtureAnswer(p, dnsmessage.RCodeSuccess, 120, 1)
	}
	r := New(testPolicy(t, nil), routes, "")
	if m := testQuery(t, r, "CaSe.Example"); m.RCode != dnsmessage.RCodeSuccess {
		t.Fatal(m.RCode)
	}
	first := calls.Load()
	if m := testQuery(t, r, "CASE.ExAmPle"); len(m.Answers) != 1 || m.Answers[0].Header.TTL == 0 {
		t.Fatal(m)
	}
	if calls.Load() > first+1 {
		t.Fatalf("second client caused another fanout: %d -> %d", first, calls.Load())
	}
	routes.mu.Lock()
	routes.allowed = nil
	routes.mu.Unlock()
	if m := testQuery(t, r, "case.example"); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("cached answer survived path revocation")
	}
}

// TestNXDomainWaitsForPositive verifies the first negative cannot cut short an outstanding address lookup.
func TestNXDomainWaitsForPositive(t *testing.T) {
	ru := Upstream{"ru", "resolver1"}
	fi := Upstream{"fi", "resolver2"}
	routes := &testRoutes{allowed: []Upstream{ru, fi}}
	negativeSent := make(chan struct{})
	routes.send = func(ctx context.Context, up Upstream, p []byte) ([]byte, error) {
		if up == ru {
			close(negativeSent)
			return fixtureAnswer(p, dnsmessage.RCodeNameError, 120, 0)
		}
		select {
		case <-negativeSent:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return fixtureAnswer(p, dnsmessage.RCodeSuccess, 20, 2)
	}
	r := New(testPolicy(t, nil), routes, "")
	if m := testQuery(t, r, "split.example"); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatal(m)
	}
	routes.mu.Lock()
	routes.allowed = []Upstream{ru}
	routes.mu.Unlock()
	if m := testQuery(t, r, "split.example"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal(m)
	}
}

// TestStaleRecovery verifies original expiry survives restart, restricted fallback and fresh negatives.
func TestStaleRecovery(t *testing.T) {
	up := Upstream{"ru", "resolver"}
	routes := &testRoutes{allowed: []Upstream{up}}
	mode := dnsmessage.RCodeSuccess
	routes.send = func(_ context.Context, _ Upstream, p []byte) ([]byte, error) { return fixtureAnswer(p, mode, 60, 3) }
	store := testPolicy(t, func(p *dnspolicy.Policy) {
		p.Settings.RetentionSeconds = 120
		p.Settings.ServeStale = true
		p.Settings.StaleWindowSeconds = 30
	})
	cache := filepath.Join(t.TempDir(), "cache.json")
	r := New(store, routes, cache)
	if m := testQuery(t, r, "old.example"); len(m.Answers) != 1 {
		t.Fatal(m)
	}
	key := cacheKey{"old.example", dnsmessage.TypeA, up}
	r.mu.Lock()
	rec := r.cache[key]
	rec.obtained = rec.obtained.Add(-70 * time.Second)
	r.cache[key] = rec
	r.mu.Unlock()
	if err := r.persist(); err != nil {
		t.Fatal(err)
	}
	r = New(store, routes, cache)
	mode = dnsmessage.RCodeServerFailure
	if m := testQuery(t, r, "old.example"); len(m.Answers) != 1 || m.Answers[0].Header.TTL != 0 {
		t.Fatal(m)
	}
	mode = dnsmessage.RCodeRefused
	if m := testQuery(t, r, "old.example"); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("served stale after permanent refusal")
	}
	mode = dnsmessage.RCodeNameError
	if m := testQuery(t, r, "old.example"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("served stale over fresh negative")
	}
	mode = dnsmessage.RCodeServerFailure
	if m := testQuery(t, r, "old.example"); m.RCode != dnsmessage.RCodeNameError {
		t.Fatal("fresh negative cache unavailable")
	}
	restarted := New(store, routes, cache)
	if m := testQuery(t, restarted, "old.example"); m.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("superseded positive resurrected after restart")
	}
}

// TestManualWarmAndExcludedAutomatic verifies two address types, independent lists, and absence of synthetic demand.
func TestManualWarmAndExcludedAutomatic(t *testing.T) {
	up := Upstream{"ru", "resolver"}
	routes := &testRoutes{allowed: []Upstream{up}}
	var calls atomic.Int64
	routes.send = func(_ context.Context, _ Upstream, p []byte) ([]byte, error) {
		calls.Add(1)
		return fixtureAnswer(p, dnsmessage.RCodeSuccess, 600, 3)
	}
	store := testPolicy(t, func(p *dnspolicy.Policy) {
		p.Settings.Threshold = 1
		p.Manual = []string{"manual.example"}
		p.Exclusions = []string{"manual.example"}
	})
	r := New(store, routes, "")
	p, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	r.schedule(context.Background(), p.Policy, &wg)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("expected A and AAAA: %d", calls.Load())
	}
	counts, _, _ := r.membership(p.Policy, time.Now())
	if len(counts) > 0 {
		t.Fatalf("synthetic visits: %+v", counts)
	}
	if m := testQuery(t, r, "manual.example"); len(m.Answers) != 1 || calls.Load() != 2 {
		t.Fatalf("cold manual entry: %+v", m)
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	_, _, auto, err := r.Observations()
	if err != nil || len(auto) != 0 {
		t.Fatalf("blacklist: %v, %v", auto, err)
	}
	p.Policy.Exclusions = []string{}
	p, err = store.Apply(p.Revision, p.Policy)
	if err != nil {
		t.Fatal(err)
	}
	_, _, auto, err = r.Observations()
	if err != nil || auto["manual.example"] != 1 {
		t.Fatalf("unblock: %v, %v", auto, err)
	}
	r.schedule(context.Background(), p.Policy, &wg)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatal("overlapping lists scheduled duplicate refresh")
	}
	r.mu.Lock()
	r.demand["manual.example"][0].at = time.Now().Add(-25 * time.Hour)
	r.mu.Unlock()
	_, _, auto, err = r.Observations()
	if err != nil || len(auto) > 0 {
		t.Fatalf("expired window: %v, %v", auto, err)
	}
}

// TestTTLZeroNeverReused verifies zero-lifetime answers trigger independent client queries and suppress background refresh.
func TestTTLZeroNeverReused(t *testing.T) {
	up := Upstream{"ru", "resolver"}
	routes := &testRoutes{allowed: []Upstream{up}}
	var calls atomic.Int32
	routes.send = func(_ context.Context, _ Upstream, p []byte) ([]byte, error) {
		calls.Add(1)
		return fixtureAnswer(p, dnsmessage.RCodeSuccess, 0, 4)
	}
	store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.Threshold = 1 })
	r := New(store, routes, "")
	testQuery(t, r, "zero.example")
	testQuery(t, r, "zero.example")
	p, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	r.schedule(context.Background(), p.Policy, &wg)
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("unexpected number of zero-TTL queries: %d", calls.Load())
	}
}

// TestMalformedQuery verifies a short DNS packet never reaches the upstream transport.
func TestMalformedQuery(t *testing.T) {
	r := New(testPolicy(t, nil), &testRoutes{send: func(context.Context, Upstream, []byte) ([]byte, error) { return nil, errors.New("unexpected exchange") }}, "")
	if _, err := r.Resolve(context.Background(), []byte{1}); err == nil {
		t.Fatal("malformed input accepted")
	}
}

// TestDemandOnlyExactNames verifies eligible non-address queries count, while IP literals and service labels cannot poison the report.
func TestDemandOnlyExactNames(t *testing.T) {
	store := testPolicy(t, func(p *dnspolicy.Policy) { p.Settings.Threshold = 1 })
	r := New(store, &testRoutes{}, "")
	for _, name := range []string{"_svc.example", "127.0.0.1", "eligible.example"} {
		packet, err := buildQuery(name, dnsmessage.TypeTXT)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Resolve(context.Background(), packet); err != nil {
			t.Fatal(err)
		}
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	_, _, counts, err := r.Observations()
	if err != nil || len(counts) != 1 || counts["eligible.example"] != 1 {
		t.Fatalf("wrong eligible observations: %v, %v", counts, err)
	}
}

// TestStaleAcrossContexts verifies one valid negative suppresses another context's stale positive.
func TestStaleAcrossContexts(t *testing.T) {
	ru := Upstream{"ru", "resolver1"}
	fi := Upstream{"fi", "resolver2"}
	var ending atomic.Bool
	routes := &testRoutes{allowed: []Upstream{ru}}
	routes.send = func(_ context.Context, up Upstream, p []byte) ([]byte, error) {
		if !ending.Load() {
			return fixtureAnswer(p, dnsmessage.RCodeSuccess, 10, 6)
		}
		if up == fi {
			return fixtureAnswer(p, dnsmessage.RCodeNameError, 30, 0)
		}
		return fixtureAnswer(p, dnsmessage.RCodeServerFailure, 0, 0)
	}
	store := testPolicy(t, func(p *dnspolicy.Policy) {
		p.Settings.RetentionSeconds = 120
		p.Settings.ServeStale = true
		p.Settings.StaleWindowSeconds = 60
	})
	r := New(store, routes, "")
	testQuery(t, r, "cross.example")
	key := cacheKey{"cross.example", dnsmessage.TypeA, ru}
	r.mu.Lock()
	saved := r.cache[key]
	saved.obtained = saved.obtained.Add(-30 * time.Second)
	r.cache[key] = saved
	r.mu.Unlock()
	ending.Store(true)
	routes.mu.Lock()
	routes.allowed = append(routes.allowed, fi)
	routes.mu.Unlock()
	if got := testQuery(t, r, "cross.example"); got.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("mixed timeout and negative must fail without stale data")
	}
	routes.mu.Lock()
	routes.allowed = []Upstream{ru}
	routes.mu.Unlock()
	if got := testQuery(t, r, "cross.example"); len(got.Answers) != 1 || got.Answers[0].Header.TTL != 0 {
		t.Fatal("remaining authorized stale unavailable")
	}
	r.mu.Lock()
	saved.obtained = saved.obtained.Add(-2 * time.Minute)
	r.cache[key] = saved
	r.mu.Unlock()
	if got := testQuery(t, r, "cross.example"); got.RCode != dnsmessage.RCodeServerFailure {
		t.Fatal("stale response beyond grace window")
	}
}
