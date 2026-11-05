package dnsresolver

import (
	"context"
	"errors"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

// Upstream identifies an authorized resolver reached over a specific exit.
type Upstream struct{ Exit, Resolver string }

// Routes supplies currently permitted contexts for the canonical name. Exchange must use the
// specified egress without host fallback, and retry a truncated UDP reply over the same path.
type Routes interface {
	Allowed(context.Context, string) ([]Upstream, error)
	Exchange(context.Context, Upstream, []byte) ([]byte, error)
}

type cacheKey struct {
	Name     string
	Kind     dnsmessage.Type
	Upstream Upstream
}
type record struct {
	answer   outcome
	obtained time.Time
}
type flight struct {
	done   chan struct{}
	record record
	err    error
}
type demandEvent struct {
	at   time.Time
	kind dnsmessage.Type
}

// Resolver coordinates router-originated queries, independent resolver contexts and policy-driven warmup.
type Resolver struct {
	store      dnspolicy.Store
	routes     Routes
	cachePath  string
	mu         sync.Mutex
	diskMu     sync.Mutex
	cursor     string
	lifecycle  context.Context
	cache      map[cacheKey]record
	flights    map[cacheKey]*flight
	retry      map[cacheKey]time.Time
	zero       map[cacheKey]bool
	demand     map[string][]demandEvent
	events     int
	overflow   time.Time
	started    bool
	generation uint64
	saved      uint64
	background chan struct{}
	foreground chan struct{}
}

const maxKeys = dnspolicy.MaxReportNames
const maxDemandEvents = 1_000_000
const exchangeTimeout = 5 * time.Second

// New constructs a resolver and loads previously persisted positive records with their original timestamps.
func New(store dnspolicy.Store, routes Routes, cachePath string) *Resolver {
	r := &Resolver{
		store: store, routes: routes, cachePath: cachePath,
		cache: make(map[cacheKey]record), flights: make(map[cacheKey]*flight),
		retry: make(map[cacheKey]time.Time), zero: make(map[cacheKey]bool),
		demand: make(map[string][]demandEvent), background: make(chan struct{}, 16),
		foreground: make(chan struct{}, 256),
	}
	if err := r.restore(); err != nil {
		log.Printf("DNS cache restore: %v", err)
	}
	return r
}

// Resolve answers one standard DNS question; the caller admits only router-facing traffic. A path
// or policy failure produces SERVFAIL; a malformed packet returns an error without any upstream call.
func (r *Resolver) Resolve(ctx context.Context, packet []byte) ([]byte, error) {
	q, err := parseQuestion(packet)
	if err != nil {
		return nil, err
	}
	policy, err := r.store.Read()
	if err != nil {
		return failure(q), nil
	}
	r.observe(q)
	allowed, err := r.routes.Allowed(ctx, q.name)
	if err != nil || len(allowed) == 0 {
		return failure(q), nil
	}
	// Canonical questions permit sharing a reply and discard client-specific optional envelope data.
	request := slices.Clone(packet)
	if q.cacheable {
		request, err = buildQuery(q.name, q.keyType)
		if err != nil {
			return failure(q), nil
		}
	}
	type attempt struct {
		up     Upstream
		result record
		err    error
	}
	ch := make(chan attempt, len(allowed))
	var pending []Upstream
	negatives := make(map[Upstream]record)
	transient := make(map[Upstream]bool)
	stale := make(map[Upstream]record)
	for _, up := range allowed {
		k := cacheKey{q.name, q.keyType, up}
		if q.cacheable {
			r.mu.Lock()
			entry, ok := r.cache[k]
			r.mu.Unlock()
			if ok {
				age := time.Since(entry.obtained)
				if age >= 0 && age < entry.answer.ttl {
					if entry.answer.positive {
						return entry.answer.reply(q, age, false), nil
					}
					negatives[up] = entry
					continue
				}
				if entry.answer.positive && age >= entry.answer.ttl {
					stale[up] = entry
				}
			}
		}
		pending = append(pending, up)
	}
	for _, up := range pending {
		select {
		case r.foreground <- struct{}{}:
		default:
			ch <- attempt{up: up, err: errors.New("DNS upstream attempt capacity reached")}
			continue
		}
		go func() {
			defer func() { <-r.foreground }()
			// Remaining resolver attempts finish even after the fastest usable answer was returned.
			bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), exchangeTimeout)
			defer cancel()
			r.mu.Lock()
			lifecycle := r.lifecycle
			r.mu.Unlock()
			if lifecycle != nil {
				stop := context.AfterFunc(lifecycle, cancel)
				defer stop()
				if lifecycle.Err() != nil {
					cancel()
				}
			}
			rec, e := r.exchange(bounded, cacheKey{q.name, q.keyType, up}, q, request, false)
			ch <- attempt{up, rec, e}
		}()
	}
	for range pending {
		select {
		case <-ctx.Done():
			return failure(q), nil
		case a := <-ch:
			if a.err != nil {
				var netErr net.Error
				transient[a.up] = errors.Is(a.err, errUpstreamTemporary) || errors.Is(a.err, context.DeadlineExceeded) || (errors.As(a.err, &netErr) && netErr.Timeout())
				continue
			}
			if !r.authorized(ctx, q.name, a.up) {
				continue
			}
			if a.result.answer.positive {
				return a.result.answer.reply(q, time.Since(a.result.obtained), false), nil
			}
			negatives[a.up] = a.result
		}
	}
	if len(negatives) > 0 {
		current, e := r.routes.Allowed(ctx, q.name)
		if e != nil || len(current) == 0 {
			return failure(q), nil
		}
		var first *record
		for _, up := range current {
			entry, ok := negatives[up]
			if !ok {
				continue
			}
			if first != nil && (first.answer.packet[3]&15) != (entry.answer.packet[3]&15) {
				return failure(q), nil
			}
			first = &entry
		}
		if first != nil {
			for _, up := range current {
				if _, ok := negatives[up]; !ok {
					return failure(q), nil
				}
			}
			return first.answer.reply(q, time.Since(first.obtained), false), nil
		}
	}
	return r.staleFallback(ctx, q, policy.Revision, transient, stale), nil
}

// staleFallback revalidates policy, every active route and the retained entry after all lookups finished.
func (r *Resolver) staleFallback(ctx context.Context, q question, revision int, transient map[Upstream]bool, stale map[Upstream]record) []byte {
	// Re-read settings in case stale serving was disabled while outstanding requests failed.
	latest, err := r.store.Read()
	if err != nil || latest.Revision != revision || !latest.Policy.Settings.ServeStale {
		return failure(q)
	}
	current, err := r.routes.Allowed(ctx, q.name)
	if err != nil || len(current) == 0 {
		return failure(q)
	}
	for _, up := range current {
		if !transient[up] {
			return failure(q)
		}
	}
	for _, up := range current {
		entry, ok := stale[up]
		r.mu.Lock()
		currentEntry, retained := r.cache[cacheKey{q.name, q.keyType, up}]
		r.mu.Unlock()
		if !ok || !retained || !currentEntry.answer.positive || !currentEntry.obtained.Equal(entry.obtained) {
			continue
		}
		age := time.Since(entry.obtained)
		if age >= entry.answer.ttl && age-entry.answer.ttl < time.Duration(latest.Policy.Settings.StaleWindowSeconds)*time.Second {
			log.Printf("DNS stale name=%s type=%d exit=%s resolver=%s age=%s expired=%s reason=all-authorized-resolvers-failed", q.name, q.keyType, up.Exit, up.Resolver, age.Round(time.Second), entry.obtained.Add(entry.answer.ttl).UTC().Format(time.RFC3339))
			return entry.answer.reply(q, age, true)
		}
	}
	return failure(q)
}

// authorized re-reads the active route policy to prevent use of a revoked resolver/exit pair.
func (r *Resolver) authorized(ctx context.Context, name string, up Upstream) bool {
	allowed, err := r.routes.Allowed(ctx, name)
	return err == nil && slices.Contains(allowed, up)
}

// exchange coalesces concurrent fills of cacheable keys and publishes only route-authorized responses.
func (r *Resolver) exchange(ctx context.Context, k cacheKey, q question, request []byte, warming bool) (record, error) {
	if !q.cacheable {
		return r.query(ctx, k, q, request)
	}
	if warming && !r.warmEligible(k.Name) {
		return record{}, errors.New("DNS name no longer eligible")
	}
	r.mu.Lock()
	if entry, ok := r.cache[k]; !warming && ok && time.Since(entry.obtained) >= 0 && time.Since(entry.obtained) < entry.answer.ttl {
		r.mu.Unlock()
		return entry, nil
	}
	if existing := r.flights[k]; existing != nil {
		r.mu.Unlock()
		select {
		case <-ctx.Done():
			return record{}, ctx.Err()
		case <-existing.done:
			return existing.record, existing.err
		}
	}
	if len(r.flights) >= maxKeys {
		r.mu.Unlock()
		return record{}, errors.New("DNS exchange capacity reached")
	}
	f := &flight{done: make(chan struct{})}
	r.flights[k] = f
	r.mu.Unlock()
	f.record, f.err = r.query(ctx, k, q, request)
	r.mu.Lock()
	invalidateDisk := false
	if f.err == nil {
		previous := r.cache[k]
		invalidateDisk = previous.answer.positive && (!f.record.answer.positive || f.record.answer.ttl == 0)
		delete(r.cache, k)
		if f.record.answer.ttl > 0 {
			delete(r.zero, k)
			if len(r.cache) < maxCacheRecords && len(f.record.answer.packet) <= maxCachePacket {
				// UDP transports may return a short slice backed by a full-size receive buffer.
				f.record.answer.packet = slices.Clone(f.record.answer.packet)
				r.cache[k] = f.record
			}
		} else if f.record.answer.positive && len(r.zero) < maxKeys {
			r.zero[k] = true
		}
		r.generation++
	}
	r.mu.Unlock()
	if invalidateDisk {
		// A fresh negative or TTL 0 must not resurrect an older positive from a last periodic save.
		if err := r.persist(); err != nil {
			// If rewriting the snapshot is impossible (for example ENOSPC), removing it
			// still prevents resurrection. Report storage failures allowing neither operation.
			if dropErr := r.discardSnapshot(); dropErr != nil {
				log.Printf("DNS cache invalidation failed: write=%v discard=%v", err, dropErr)
			} else {
				log.Printf("DNS cache snapshot discarded after invalidation failure: %v", err)
			}
		}
	}
	r.mu.Lock()
	delete(r.flights, k)
	close(f.done)
	r.mu.Unlock()
	return f.record, f.err
}

// query exchanges and validates one DNS packet using an authorized transport and an independent transaction ID.
func (r *Resolver) query(ctx context.Context, k cacheKey, q question, request []byte) (record, error) {
	out, id, err := randomized(request)
	if err != nil {
		return record{}, err
	}
	if !r.authorized(ctx, k.Name, k.Upstream) {
		return record{}, errors.New("DNS path not allowed")
	}
	response, err := r.routes.Exchange(ctx, k.Upstream, out)
	if err != nil {
		return record{}, err
	}
	answer, err := classify(q, id, response)
	if err != nil {
		return record{}, err
	}
	if !r.authorized(ctx, k.Name, k.Upstream) {
		return record{}, errors.New("DNS path revoked")
	}
	return record{answer, time.Now()}, nil
}

// observe counts one ingress request before cache lookup and ignores upstream and background traffic by construction.
func (r *Resolver) observe(q question) {
	if q.message.Questions[0].Class != dnsmessage.ClassINET || !dnspolicy.IsCanonicalDomain(q.name) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	events := r.demand[q.name]
	if len(events) == 0 && len(r.demand) >= maxKeys || r.events >= maxDemandEvents {
		r.overflow = now
		return
	}
	r.demand[q.name] = append(events, demandEvent{now, q.keyType})
	r.events++
}

// membership prunes expired observations and returns per-name client counts and observed address types.
func (r *Resolver) membership(p dnspolicy.Policy, now time.Time) (map[string]int, map[string][]dnsmessage.Type, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := now.Add(-time.Duration(p.Settings.WindowHours) * time.Hour)
	counts := make(map[string]int)
	types := make(map[string][]dnsmessage.Type)
	for name, events := range r.demand {
		i := 0
		for i < len(events) && !events[i].at.After(cutoff) {
			i++
		}
		r.events -= i
		if i == len(events) {
			delete(r.demand, name)
			continue
		}
		remaining := events[i:]
		if i >= 128 && i >= len(remaining) {
			remaining = slices.Clone(remaining)
		}
		events = remaining
		r.demand[name] = events
		counts[name] = len(events)
		for _, e := range events {
			if (e.kind == dnsmessage.TypeA || e.kind == dnsmessage.TypeAAAA) && !slices.Contains(types[name], e.kind) {
				types[name] = append(types[name], e.kind)
			}
			if len(types[name]) == 2 {
				break
			}
		}
	}
	for name := range counts {
		if len(types[name]) == 0 {
			types[name] = []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
		}
	}
	return counts, types, r.overflow.After(cutoff)
}

// warmEligible verifies the individual name against the latest settings and real client window before an update.
func (r *Resolver) warmEligible(name string) bool {
	s, err := r.store.Read()
	if err != nil {
		return false
	}
	p := s.Policy
	if slices.Contains(p.Manual, name) {
		return true
	}
	if !p.Settings.AutomaticEnabled || slices.Contains(p.Exclusions, name) {
		return false
	}
	cutoff := time.Now().Add(-time.Duration(p.Settings.WindowHours) * time.Hour)
	r.mu.Lock()
	defer r.mu.Unlock()
	events := r.demand[name]
	return len(events) >= p.Settings.Threshold && events[len(events)-p.Settings.Threshold].at.After(cutoff)
}

// Observations returns measured automatic membership only while the worker is running and its window is complete.
func (r *Resolver) Observations() (time.Time, int, map[string]int, error) {
	r.mu.Lock()
	running := r.started
	r.mu.Unlock()
	if !running {
		return time.Time{}, 0, nil, errors.New("DNS worker unavailable")
	}
	s, err := r.store.Read()
	if err != nil {
		return time.Time{}, 0, nil, err
	}
	now := time.Now()
	counts, _, overflow := r.membership(s.Policy, now)
	if overflow {
		return time.Time{}, 0, nil, errors.New("DNS demand observation capacity exceeded")
	}
	if !s.Policy.Settings.AutomaticEnabled {
		return now, s.Revision, map[string]int{}, nil
	}
	selected, err := dnspolicy.SelectWarmDomains(s.Policy.Settings.Threshold, counts, s.Policy.Manual, s.Policy.Exclusions)
	if err != nil {
		return time.Time{}, 0, nil, err
	}
	result := make(map[string]int, len(selected.Automatic))
	for _, n := range selected.Automatic {
		result[n] = counts[n]
	}
	return now, s.Revision, result, nil
}
