package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/Artik-Man/Hestia/internal/routing"
)

const (
	qualitySettingsFile = "/var/lib/hestia-quality-settings/settings.json"
	qualityRuntimeDir   = "/run/hestia-quality"
)

// readQualityPaths reads the path bindings exported from the installed backend generation.
func readQualityPaths() ([]quality.Path, error) {
	data, err := os.ReadFile(filepath.Join(qualityRuntimeDir, "paths.json"))
	if err != nil {
		return nil, err
	}
	var paths []quality.Path
	if err := json.Unmarshal(data, &paths); err != nil {
		return nil, err
	}
	return paths, nil
}

// startQuality installs device bindings before loading probe settings so a settings error still permits carrier checks.
func (w *watcher) startQuality(ctx context.Context) error {
	paths, err := readQualityPaths()
	if err != nil {
		return err
	}
	w.devices = make(map[string]string, len(paths))
	for _, path := range paths {
		if path.Device != "" || path.SocksAddress != "" {
			w.devices[path.ID] = path.Device
		}
	}
	engine, err := quality.NewEngine(qualitySettingsFile)
	if err != nil {
		return err
	}
	w.relayReady = make(map[string]*atomic.Bool)
	w.relayProbes = make(chan struct{}, 32)
	candidates := make(map[string][]quality.Path)
	publicPaths := make([]quality.Path, 0, len(paths))
	for _, path := range paths {
		if path.Relay != "" {
			candidates[path.Relay] = append(candidates[path.Relay], path)
			continue
		}
		publicPaths = append(publicPaths, path)
		if path.Hysteria2 {
			ready := new(atomic.Bool)
			w.relayReady[path.ID] = ready
			go w.monitorRelay(ctx, path, ready)
		}
	}
	for id, paths := range candidates {
		ready := new(atomic.Bool)
		w.relayReady[id] = ready
		go w.monitorCandidates(ctx, id, paths, ready)
	}
	go engine.Run(ctx, func(context.Context) ([]quality.Path, error) { return publicPaths, nil })
	w.quality = engine
	return nil
}

// qualityOrder ranks eligible exits by their complete arithmetic mean, retaining current preference on a tie.
func qualityOrder(g routing.Group, health map[string]bool, current string, scores map[string]quality.Result) panelmodel.QualityGroup {
	group := panelmodel.QualityGroup{ID: g.ID, Name: g.Name, Connections: make([]panelmodel.QualityConnection, 0, len(g.Exits))}
	for _, id := range g.Exits {
		group.Connections = append(group.Connections, panelmodel.QualityConnection{ID: id, Available: health[id], Result: scores[id]})
	}
	slices.SortStableFunc(group.Connections, func(a, b panelmodel.QualityConnection) int {
		if a.Available != b.Available {
			if a.Available {
				return -1
			}
			return 1
		}
		x, y := a.Result.Overall, b.Result.Overall
		switch {
		case x != nil && y == nil:
			return -1
		case x == nil && y != nil:
			return 1
		case x != nil && *x > *y:
			return -1
		case y != nil && *y > *x:
			return 1
		case a.ID == current && b.ID != current:
			return -1
		case b.ID == current && a.ID != current:
			return 1
		default:
			return 0
		}
	})
	return group
}

// corroborated requires better delivery to two distinct destination IPs before moving a healthy selector.
func corroborated(candidate, current quality.Result) bool {
	type measurement struct{ protocol, target string }
	baseline := make(map[measurement]float64)
	for _, check := range current.Checks {
		for _, target := range check.Targets {
			if target.Score != nil && target.Samples >= 3 {
				baseline[measurement{check.Protocol, target.Target}] = *target.Score
			}
		}
	}
	better := make(map[netip.Addr]bool)
	for _, check := range candidate.Checks {
		for _, target := range check.Targets {
			previous, ok := baseline[measurement{check.Protocol, target.Target}]
			if ok && target.Score != nil && target.Samples >= 3 && *target.Score > previous {
				if ip, err := netip.ParseAddr(target.Target); err == nil {
					better[ip.Unmap()] = true
				} else if addr, err := netip.ParseAddrPort(target.Target); err == nil {
					better[addr.Addr().Unmap()] = true
				}
			}
		}
	}
	return len(better) >= 2
}

// qualityTarget chooses a measured improvement or retains an eligible current exit while evidence accumulates.
func qualityTarget(group panelmodel.QualityGroup, current string) string {
	if len(group.Connections) == 0 || !group.Connections[0].Available {
		return ""
	}
	index := slices.IndexFunc(group.Connections, func(row panelmodel.QualityConnection) bool { return row.ID == current && row.Available })
	if index < 0 {
		return group.Connections[0].ID
	}
	baseline := group.Connections[index].Result
	for _, candidate := range group.Connections[:index] {
		score := candidate.Result.Overall
		if baseline.Overall != nil && score != nil && *score > *baseline.Overall && corroborated(candidate.Result, baseline) {
			return candidate.ID
		}
	}
	return current
}

// publishQuality atomically publishes a complete observation for the unprivileged panel.
func publishQuality(report panelmodel.QualityReport) error {
	f, err := os.CreateTemp(qualityRuntimeDir, ".report-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = json.NewEncoder(f).Encode(report)
	if err == nil {
		err = f.Chmod(0644)
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(qualityRuntimeDir, "report.json"))
}

// refreshQuality loads atomically saved settings before scoring the next selector cycle.
func (w *watcher) refreshQuality() error {
	settings, err := quality.LoadSettings(qualitySettingsFile)
	if err != nil {
		return err
	}
	return w.quality.ApplySettings(settings)
}

// monitorRelay publishes reachability independently of optional quality scoring and stops with the watcher.
func (w *watcher) monitorRelay(ctx context.Context, path quality.Path, ready *atomic.Bool) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	var window relayWindow
	for ctx.Err() == nil {
		window.observe(w.probeRelay(ctx, path))
		ready.Store(window.available)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// probeRelay limits concurrent peer checks across all Hysteria profiles and abandons queued probes at shutdown.
func (w *watcher) probeRelay(ctx context.Context, path quality.Path) bool {
	select {
	case w.relayProbes <- struct{}{}:
		defer func() { <-w.relayProbes }()
		return quality.HysteriaReady(ctx, path)
	case <-ctx.Done():
		return false
	}
}
