package quality

import (
	"context"
	"reflect"
	"slices"
)

// groupWorker owns a group's isolated probe history and cancellation boundary.
type groupWorker struct {
	engine *Engine
	ids    []string
	cancel context.CancelFunc
}

// GroupEngine serially reconciles group schedules while each worker measures its own paths.
// Configuration methods are called by the controller reconciliation loop only.
type GroupEngine struct {
	settings Settings
	paths    []Path
	workers  map[string]groupWorker
}

// NewGroupEngine loads the migration seed and group overrides without starting unscoped probes.
func NewGroupEngine(path string, paths ...Path) (*GroupEngine, error) {
	settings, err := LoadSettings(path)
	if err != nil {
		return nil, err
	}
	return &GroupEngine{settings: settings, paths: slices.Clone(paths), workers: map[string]groupWorker{}}, nil
}

// Settings returns a detached persisted configuration for report freshness checks.
func (g *GroupEngine) Settings() Settings { return cloneSettings(g.settings) }

// ApplySettings updates only workers whose group schedule changed.
func (g *GroupEngine) ApplySettings(settings Settings) error {
	if err := settings.Validate(); err != nil {
		return err
	}
	for id, worker := range g.workers {
		config := settings.ForGroup(id)
		if err := worker.engine.ApplySettings(Settings{WindowMinutes: config.WindowMinutes, Checks: config.Checks}); err != nil {
			return err
		}
	}
	g.settings = cloneSettings(settings)
	return nil
}

// Configure starts all group paths, including reserves, and cancels obsolete topology generations.
func (g *GroupEngine) Configure(ctx context.Context, groups map[string][]string) {
	for id, worker := range g.workers {
		ids, ok := groups[id]
		if !ok || !reflect.DeepEqual(ids, worker.ids) {
			worker.cancel()
			delete(g.workers, id)
		}
	}
	for id, ids := range groups {
		if _, ok := g.workers[id]; ok {
			continue
		}
		paths := make([]Path, 0, len(ids))
		for _, p := range g.paths {
			if slices.Contains(ids, p.ID) {
				paths = append(paths, p)
			}
		}
		config := g.settings.ForGroup(id)
		engine := newConfiguredEngine(Settings{WindowMinutes: config.WindowMinutes, Checks: config.Checks}, paths...)
		workerCtx, cancel := context.WithCancel(ctx)
		g.workers[id] = groupWorker{engine: engine, ids: slices.Clone(ids), cancel: cancel}
		go engine.Run(workerCtx)
	}
}

// Snapshot returns only one group's observations even when exit IDs are shared between groups.
func (g *GroupEngine) Snapshot(id string, ids []string) (GroupSettings, map[string]Result) {
	if worker, ok := g.workers[id]; ok {
		settings, results := worker.engine.Snapshot(ids)
		return GroupSettings{WindowMinutes: settings.WindowMinutes, Checks: settings.Checks}, results
	}
	return g.settings.ForGroup(id), map[string]Result{}
}

// Reset clears each group's completed observations and invalidates in-flight rounds independently.
func (g *GroupEngine) Reset() {
	for _, worker := range g.workers {
		worker.engine.Reset()
	}
}
