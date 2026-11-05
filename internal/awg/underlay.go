package awg

import (
	"math/bits"
	"time"
)

// pathQuality tracks scoped probe losses separately from failures of the actual encrypted peer path.
type pathQuality struct {
	known, healthy            bool
	success, failure, samples int
	misses                    uint8
	retryAfter                time.Time
	backoff                   time.Duration
	peerSuccess               int
}

// observe demotes after three consecutive losses or three in eight samples and recovers after three consecutive successes.
func (p *pathQuality) observe(ok bool) {
	p.misses <<= 1
	if p.samples < 8 {
		p.samples++
	}
	if ok {
		p.failure = 0
		if p.success < 3 {
			p.success++
		}
		if !p.known || p.success == 3 {
			p.healthy = true
		}
	} else {
		p.misses |= 1
		p.success = 0
		if p.failure < 3 {
			p.failure++
		}
		if p.failure == 3 || (p.samples == 8 && bits.OnesCount8(p.misses) >= 3) {
			p.healthy = false
		}
	}
	p.known = true
}

// quarantine backs off trials of a candidate whose unrelated HTTPS probe works but whose WireGuard peer does not.
func (p *pathQuality) quarantine(now time.Time) {
	p.peerSuccess = 0
	p.backoff = min(30*time.Minute, max(30*time.Second, 2*p.backoff))
	p.retryAfter = now.Add(p.backoff)
}

// confirmPeer releases an accumulated backoff only after three successful probes through the actual tunnel.
func (p *pathQuality) confirmPeer() {
	if p.peerSuccess < 3 {
		p.peerSuccess++
	}
	if p.peerSuccess == 3 {
		p.retryAfter = time.Time{}
		p.backoff = 0
	}
}

// preferredUnderlay selects the highest-priority healthy eligible path, returning -1 while every candidate is unavailable.
func preferredUnderlay(paths []pathQuality, now time.Time) int {
	for i, path := range paths {
		if path.healthy && !now.Before(path.retryAfter) {
			return i
		}
	}
	return -1
}

// activationUnderlay prefers an eligible, not-yet-quarantined candidate before retrying an old failure during initial activation.
func activationUnderlay(paths []pathQuality, now time.Time) int {
	for i, path := range paths {
		if path.healthy && path.backoff == 0 {
			return i
		}
	}
	return preferredUnderlay(paths, now)
}
