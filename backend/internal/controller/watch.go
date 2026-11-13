package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/Artik-Man/Hestia/internal/routing"
)

type watcher struct {
	relayProbes  chan struct{}
	relayReady   map[string]*atomic.Bool
	devices      map[string]string
	carrier      func(string) panelmodel.CarrierState
	quality      *quality.GroupEngine
	qualityReset int64
	client       *http.Client
	base         string
	desired      *Config
	pinned       bool
	confirmed    map[string]string
	healthyAWG   func(string) bool
}

// newWatcher starts reconciliation with no desired snapshot or confirmed targets and selected platform link observation.
func newWatcher(client *http.Client, base string) *watcher {
	return &watcher{client: client, base: base, confirmed: make(map[string]string), healthyAWG: AWGHeartbeatHealthy, carrier: installedCarrier()}
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
	health := make(map[string]bool, len(w.desired.Healthy))
	for id, available := range w.desired.Healthy {
		device, mapped := w.devices[id]
		state := panelmodel.CarrierUp
		if device != "" {
			state = w.carrier(device)
		}
		mappedOK := w.devices == nil || mapped
		health[id] = available && mappedOK && state == panelmodel.CarrierUp
		if available && mappedOK && device != "" && state == panelmodel.CarrierUnknown {
			failures = append(failures, fmt.Errorf("carrier state is unknown for exit %s on interface %s", id, device))
		}
	}
	for id, kind := range w.desired.ConnectorKinds {
		if kind == "hysteria2" {
			ready := w.relayReady[id]
			health[id] = health[id] && ready != nil && ready.Load()
		}
		if kind == "awg" && !w.healthyAWG(id) {
			health[id] = false
		}
	}
	var observation panelmodel.QualityReport
	if w.quality != nil {
		if err := w.refreshQuality(); err != nil {
			failures = append(failures, err)
		}
		groups := make(map[string][]string, len(w.desired.Groups))
		for _, group := range w.desired.Groups {
			groups[group.ID] = group.Exits
		}
		w.quality.Configure(ctx, groups)
		observation.Settings = w.quality.Settings()
		observation.CapturedAt = time.Now().UTC().Format(time.RFC3339Nano)
		observation.Groups = []panelmodel.QualityGroup{}
	}
	for _, g := range w.desired.Groups {
		if ctx.Err() != nil {
			break
		}
		exit, outcome := routing.SelectExit(g, health)
		var group panelmodel.QualityGroup
		var scores map[string]quality.Result
		var groupSettings quality.GroupSettings
		reason := routing.MatchReason("availability_snapshot")
		target := exit
		if outcome == routing.Block {
			target = deny
		}
		if w.quality != nil {
			groupSettings, scores = w.quality.Snapshot(g.ID, g.Exits)
			group = qualityOrder(g, health, "", scores)
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		changed, err := ownedDecision(requestCtx, w.client, w.base, g, func(current string) string {
			if w.quality != nil {
				group = qualityOrder(g, health, current, scores)
				exit = qualityTarget(group, current)
				if exit != "" {
					target = exit
					if health[current] && group.Connections[0].Result.Overall != nil {
						reason = "quality_scores"
					}
				}
			}
			return target
		})
		cancel()
		if w.quality != nil {
			group.Settings = groupSettings
			for i := range group.Connections {
				group.Connections[i].Active = err == nil && group.Connections[i].ID == target
			}
			observation.Groups = append(observation.Groups, group)
		}
		if err != nil {
			delete(w.confirmed, g.ID)
			failures = append(failures, fmt.Errorf("group %s: %w", g.ID, err))
			continue
		}
		w.pinned = true
		if changed || w.confirmed[g.ID] != target {
			results = append(results, Result{Time: time.Now().UTC(), Group: g.ID, Exit: exit, Reason: reason, Outcome: outcome, SelectorTarget: target})
			w.confirmed[g.ID] = target
		}
	}
	if w.quality != nil && ctx.Err() == nil {
		failures = append(failures, publishQuality(observation))
	}
	return results, errors.Join(failures...)
}

// Watch serially reloads an atomically replaced availability file and repairs selector drift.
func Watch(ctx context.Context, path string, interval time.Duration, enableQuality bool, report func(Result) error, warn func(error)) error {
	if interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	client := newClient()
	defer client.CloseIdleConnections()
	w := newWatcher(client, localAPI)
	if enableQuality {
		w.devices = make(map[string]string)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastError := ""
	var lastProbeInit time.Time
	for ctx.Err() == nil {
		if enableQuality && w.quality == nil && time.Since(lastProbeInit) >= 5*time.Second {
			lastProbeInit = time.Now()
			if initErr := w.startQuality(ctx); initErr != nil {
				warn(fmt.Errorf("quality measurements unavailable: %w", initErr))
			}
		}
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
