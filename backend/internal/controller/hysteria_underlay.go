package controller

import (
	"context"
	"math/bits"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// relayWindow applies the same loss and recovery thresholds as encrypted WireGuard transports.
type relayWindow struct {
	misses             uint8
	samples, successes int
	available          bool
}

// observe admits an initially working peer, demotes persistent loss and requires three successes to recover.
func (w *relayWindow) observe(ok bool) {
	w.misses <<= 1
	w.samples = min(8, w.samples+1)
	if ok {
		w.successes = min(3, w.successes+1)
		if w.samples == 1 || w.successes == 3 {
			w.available = true
		}
	} else {
		w.misses |= 1
		w.successes = 0
		if w.samples >= 3 && w.misses&7 == 7 || w.samples == 8 && bits.OnesCount8(w.misses) >= 3 {
			w.available = false
		}
	}
}

// monitorCandidates probes each candidate's independent QUIC client and confirms the ordered selection before publishing readiness.
func (w *watcher) monitorCandidates(ctx context.Context, id string, paths []quality.Path, ready *atomic.Bool) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	windows := make([]relayWindow, len(paths))
	group := routing.Group{ID: id}
	for _, path := range paths {
		group.Exits = append(group.Exits, path.ID)
	}
	for ctx.Err() == nil {
		var probes sync.WaitGroup
		for index, path := range paths {
			probes.Add(1)
			go func() {
				defer probes.Done()
				windows[index].observe(w.probeRelay(ctx, path))
			}()
		}
		probes.Wait()
		target := deny
		for i, state := range windows {
			if state.available {
				target = paths[i].ID
				break
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 3*time.Second)
		_, err := ownedReconcile(attempt, w.client, w.base, group, target)
		cancel()
		ready.Store(err == nil && target != deny)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Hysteria2ActiveUnderlay returns the confirmed live candidate of a manual selector, or empty when blocked or unavailable.
func Hysteria2ActiveUnderlay(id string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := newClient()
	defer client.CloseIdleConnections()
	state, err := readSelector(ctx, client, localAPI+"/proxies/"+url.PathEscape(id))
	if err != nil || state.Type != "Selector" {
		return ""
	}
	candidate, ok := strings.CutPrefix(state.Now, "_hy2/"+id+"/")
	if !ok {
		return ""
	}
	return candidate
}
