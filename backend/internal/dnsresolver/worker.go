package dnsresolver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

const maxCacheRecords = 4096
const maxCachePacket = 8192

type diskEntry struct {
	Key      cacheKey
	Obtained time.Time
	Packet   []byte
}

// restore validates each saved positive transaction and original timestamp before replacing the cache.
func (r *Resolver) restore() error {
	if r.cachePath == "" {
		return nil
	}
	f, err := os.Open(r.cachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	const maxBytes = 64 << 20
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > maxBytes {
		return errors.New("oversized DNS cache")
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxBytes+1))
	var entries []diskEntry
	if err := decoder.Decode(&entries); err != nil {
		return err
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF || len(entries) > maxCacheRecords {
		return errors.New("invalid DNS cache")
	}
	now := time.Now()
	cache := make(map[cacheKey]record, len(entries))
	for _, item := range entries {
		key := item.Key
		if item.Obtained.IsZero() || item.Obtained.After(now) || len(item.Packet) < 12 || len(item.Packet) > maxCachePacket || key.Upstream.Exit == "" || key.Upstream.Resolver == "" || key.Kind != dnsmessage.TypeA && key.Kind != dnsmessage.TypeAAAA {
			continue
		}
		request, err := buildQuery(key.Name, key.Kind)
		if err != nil {
			continue
		}
		q, err := parseQuestion(request)
		if err != nil || q.name != key.Name {
			continue
		}
		answer, err := classify(q, binary.BigEndian.Uint16(item.Packet), item.Packet)
		if err != nil || !answer.positive || answer.ttl <= 0 {
			continue
		}
		cache[key] = record{answer, item.Obtained}
	}
	r.cache = cache
	return nil
}

// persist writes only positive records and atomically replaces a worker-private cache snapshot.
func (r *Resolver) persist() error {
	if r.cachePath == "" {
		return nil
	}
	r.diskMu.Lock()
	defer r.diskMu.Unlock()
	r.mu.Lock()
	gen := r.generation
	if gen == r.saved {
		r.mu.Unlock()
		return nil
	}
	entries := make([]diskEntry, 0, len(r.cache))
	for key, entry := range r.cache {
		if entry.answer.positive {
			entries = append(entries, diskEntry{key, entry.obtained, entry.answer.packet})
		}
	}
	r.mu.Unlock()
	dir := filepath.Dir(r.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".dns-cache-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(entries)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), r.cachePath); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return err
	}
	r.mu.Lock()
	r.saved = gen
	r.mu.Unlock()
	return nil
}

// discardSnapshot removes obsolete durable positives and syncs their directory after an invalidation write fails.
func (r *Resolver) discardSnapshot() error {
	r.diskMu.Lock()
	defer r.diskMu.Unlock()
	if err := os.Remove(r.cachePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.mu.Lock()
	r.saved = 0
	r.mu.Unlock()
	dir, err := os.Open(filepath.Dir(r.cachePath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Run refreshes eligible names and periodically persists positive cache data until cancellation.
// Only one Run may be active; positive A and AAAA records are eligible for automatic scheduling.
func (r *Resolver) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.lifecycle = ctx
	r.mu.Unlock()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var workers sync.WaitGroup
	var savedAt time.Time
	for ctx.Err() == nil {
		s, err := r.store.Read()
		if err == nil {
			r.schedule(ctx, s.Policy, &workers)
		}
		if time.Since(savedAt) >= 10*time.Second {
			if err := r.persist(); err != nil {
				log.Printf("DNS cache save: %v", err)
			}
			savedAt = time.Now()
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	r.mu.Lock()
	r.started = false
	r.mu.Unlock()
	workers.Wait()
	if err := r.persist(); err != nil {
		log.Printf("DNS cache save on shutdown: %v", err)
	}
}

// schedule computes current eligibility and dispatches only due keys within the background concurrency bound.
func (r *Resolver) schedule(ctx context.Context, p dnspolicy.Policy, workers *sync.WaitGroup) {
	now := time.Now()
	counts, kinds, _ := r.membership(p, now)
	if !p.Settings.AutomaticEnabled {
		counts = nil
	}
	sel, err := dnspolicy.SelectWarmDomains(p.Settings.Threshold, counts, p.Manual, p.Exclusions)
	if err != nil {
		return
	}
	for _, name := range p.Manual {
		kinds[name] = []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	}
	retention := time.Duration(p.Settings.RetentionSeconds) * time.Second
	r.mu.Lock()
	for k, entry := range r.cache {
		life := entry.answer.ttl
		if entry.answer.positive {
			life += retention
		}
		if !now.Before(entry.obtained.Add(life)) {
			delete(r.cache, k)
			r.generation++
		}
	}
	for k := range r.zero {
		if _, active := slices.BinarySearch(sel.Effective, k.Name); !active {
			delete(r.zero, k)
		}
	}
	for k, retry := range r.retry {
		if !now.Before(retry) {
			delete(r.retry, k)
		}
	}
	r.mu.Unlock()
	// Rotate the starting name so short TTLs or slow paths cannot monopolize limited slots.
	start, _ := slices.BinarySearch(sel.Effective, r.cursor)
	for offset := range min(32, len(sel.Effective)) {
		i := (start + offset) % len(sel.Effective)
		name := sel.Effective[i]
		r.cursor = sel.Effective[(i+1)%len(sel.Effective)]
		if ctx.Err() != nil || time.Since(now) > 2*time.Second {
			return
		}
		paths, err := r.routes.Allowed(ctx, name)
		if err != nil {
			continue
		}
		for _, kind := range kinds[name] {
			request, err := buildQuery(name, kind)
			if err != nil {
				continue
			}
			q, err := parseQuestion(request)
			if err != nil {
				continue
			}
			for _, up := range paths {
				k := cacheKey{name, kind, up}
				r.mu.Lock()
				due := r.nextDue(k, time.Duration(p.Settings.IntervalMinutes)*time.Minute)
				_, cached := r.cache[k]
				if now.Before(due) || r.flights[k] != nil || r.zero[k] || (!cached && len(r.zero) >= maxKeys) {
					r.mu.Unlock()
					continue
				}
				select {
				case r.background <- struct{}{}:
					// Bound repeated attempts on failures and short-TTL answers.
					r.retry[k] = now.Add(min(5*time.Second, time.Duration(p.Settings.IntervalMinutes)*time.Minute))
				default:
					r.mu.Unlock()
					return
				}
				r.mu.Unlock()
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-r.background }()
					bounded, cancel := context.WithTimeout(ctx, exchangeTimeout)
					defer cancel()
					rec, err := r.exchange(bounded, k, q, request, true)
					if err == nil {
						log.Printf("DNS warm name=%s type=%d exit=%s resolver=%s positive=%t ttl=%s", k.Name, k.Kind, up.Exit, up.Resolver, rec.answer.positive, rec.answer.ttl)
					} else if bounded.Err() == nil {
						log.Printf("DNS warm name=%s type=%d exit=%s resolver=%s: %v", k.Name, k.Kind, up.Exit, up.Resolver, err)
					}
				}()
			}
		}
	}
}

// nextDue returns the earlier of the configured interval and the final 10% of the TTL,
// while preserving a minimum retry interval. Caller holds the resolver mutex.
func (r *Resolver) nextDue(k cacheKey, interval time.Duration) time.Time {
	retry := r.retry[k]
	rec, ok := r.cache[k]
	if !ok {
		return retry
	}
	due := rec.obtained.Add(min(interval, rec.answer.ttl-rec.answer.ttl/10))
	if retry.After(due) {
		return retry
	}
	return due
}
