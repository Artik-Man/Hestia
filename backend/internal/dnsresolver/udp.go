package dnsresolver

import (
	"container/list"
	"net/netip"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

const maxUDPTransactions = 32768

type udpKey struct {
	peer  netip.AddrPort
	id    uint16
	name  string
	kind  dnsmessage.Type
	class dnsmessage.Class
}
type udpEntry struct {
	key       udpKey
	firstSeen time.Time
}
type udpTracker struct {
	mu      sync.Mutex
	entries map[udpKey]*list.Element
	recent  list.List
	stats   dnspolicy.DNSClientUDP
}

// record returns whether to suppress demand for this datagram due to a known retry or a full transaction history.
func (t *udpTracker) record(key udpKey, window time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.stats.Attempts++
	if t.entries == nil {
		t.entries = make(map[udpKey]*list.Element)
	}
	t.pruneLocked(now.Add(-window))
	if e := t.entries[key]; e != nil {
		t.stats.RetriedAttempts++
		return true
	}
	if len(t.entries) >= maxUDPTransactions {
		t.stats.UnclassifiedAttempts++
		return true
	}
	t.entries[key] = t.recent.PushBack(udpEntry{key, now})
	return false
}

// pruneLocked forgets transactions at or before the exclusive demand-window cutoff while retaining lifetime counters.
// The caller holds t.mu.
func (t *udpTracker) pruneLocked(cutoff time.Time) {
	for first := t.recent.Front(); first != nil; first = t.recent.Front() {
		e := first.Value.(udpEntry)
		if e.firstSeen.After(cutoff) {
			break
		}
		delete(t.entries, e.key)
		t.recent.Remove(first)
	}
}

// ClientUDPStats snapshots observed router-side attempts; successful delivery cannot be inferred from UDP sends.
func (r *Resolver) ClientUDPStats() dnspolicy.DNSClientUDP {
	r.udp.mu.Lock()
	defer r.udp.mu.Unlock()
	return r.udp.stats
}
