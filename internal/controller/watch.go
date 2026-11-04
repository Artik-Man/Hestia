package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"time"

	"github.com/Artik-Man/Hestia/internal/routing"
)

type watcher struct {
	client    *http.Client
	base      string
	desired   *Config
	pinned    bool
	confirmed map[string]string
}

// newWatcher starts reconciliation with no desired snapshot or confirmed targets.
func newWatcher(client *http.Client, base string) *watcher {
	return &watcher{client: client, base: base, confirmed: make(map[string]string)}
}

// CheckSnapshot validates a candidate without connecting to sing-box.
func CheckSnapshot(data []byte) (Config, error) {
	cfg, err := Decode(data)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	if d := routing.Decide(cfg.Groups, cfg.Lists, cfg.Healthy, ""); d.Outcome == routing.Reject {
		return Config{}, fmt.Errorf("invalid routing configuration")
	}
	return cfg, nil
}

// load replaces the desired snapshot only after validation. Once any group has
// been confirmed, the snapshot may change availability but must retain the topology.
func (w *watcher) load(data []byte) error {
	cfg, err := CheckSnapshot(data)
	if err != nil {
		return err
	}
	if w.pinned && (!reflect.DeepEqual(w.desired.Groups, cfg.Groups) || !reflect.DeepEqual(w.desired.Lists, cfg.Lists)) {
		return fmt.Errorf("group and domain topology must stay fixed while watching availability")
	}
	w.desired = &cfg
	return nil
}

// step tries the candidate snapshot and reconciles selectors even if the load
// fails, using the previous valid snapshot when one is available.
func (w *watcher) step(ctx context.Context, data []byte) ([]Result, error) {
	err := w.load(data)
	results, reconcileErr := w.sync(ctx)
	return results, errors.Join(err, reconcileErr)
}

// sync reconciles all groups against the desired snapshot. It returns confirmed
// changes alongside any failures so one unavailable selector does not prevent
// other groups from making progress.
func (w *watcher) sync(ctx context.Context) ([]Result, error) {
	if w.desired == nil {
		return nil, nil
	}
	var results []Result
	var failures []error
	for _, g := range w.desired.Groups {
		if ctx.Err() != nil {
			break
		}
		exit, outcome := routing.SelectExit(g, w.desired.Healthy)
		target := exit
		if outcome == routing.Block {
			target = deny
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		changed, err := reconcile(requestCtx, w.client, w.base, g, target)
		cancel()
		if err != nil {
			delete(w.confirmed, g.ID)
			failures = append(failures, fmt.Errorf("group %s: %w", g.ID, err))
			continue
		}
		w.pinned = true
		if changed || w.confirmed[g.ID] != target {
			results = append(results, Result{Time: time.Now().UTC(), Group: g.ID, Exit: exit, Reason: "availability_snapshot", Outcome: outcome, SelectorTarget: target})
			w.confirmed[g.ID] = target
		}
	}
	return results, errors.Join(failures...)
}

// Watch serially reloads an atomically replaced availability file and repairs selector drift.
func Watch(ctx context.Context, path string, interval time.Duration, report func(Result) error, warn func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	client := newClient()
	defer client.CloseIdleConnections()
	w := newWatcher(client, localAPI)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastError := ""
	for ctx.Err() == nil {
		data, readErr := os.ReadFile(path)
		var results []Result
		var err error
		if readErr == nil {
			results, err = w.step(ctx, data)
		} else {
			results, err = w.sync(ctx)
			err = errors.Join(readErr, err)
		}
		if ctx.Err() != nil {
			return nil
		}
		for _, r := range results {
			if err := report(r); err != nil {
				return err
			}
		}
		if err != nil {
			if err.Error() != lastError {
				warn(err)
				lastError = err.Error()
			}
		} else {
			lastError = ""
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}
