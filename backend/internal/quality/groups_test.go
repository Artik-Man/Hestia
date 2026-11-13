package quality

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestGroupSettingsMigration preserves independent legacy copies and gives new groups a fresh default schedule.
func TestGroupSettingsMigration(t *testing.T) {
	settings := DefaultSettings()
	settings.WindowMinutes = 20
	first := settings.ForGroup("ru")
	first.Checks[0].Targets[0] = "77.88.8.8:53"
	if settings.Checks[0].Targets[0] != "1.1.1.1:53" {
		t.Fatal("group aliases legacy seed")
	}
	settings.Groups = map[string]GroupSettings{"ru": first, "world": settings.ForGroup("world")}
	if settings.ForGroup("world").WindowMinutes != 20 || settings.ForGroup("new").WindowMinutes != 60 {
		t.Fatal("migration/default window")
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := SaveSettings(path, settings); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSettings(path)
	if err != nil || loaded.ForGroup("ru").Checks[0].Targets[0] != "77.88.8.8:53" {
		t.Fatal(loaded, err)
	}
}

// TestGroupEngineIsolation keeps scores and changed-check invalidation separate for a shared connection ID.
func TestGroupEngineIsolation(t *testing.T) {
	manager, err := NewGroupEngine(filepath.Join(t.TempDir(), "settings.json"), Path{ID: "shared"}, Path{ID: "reserve"})
	if err != nil {
		t.Fatal(err)
	}
	settings := DefaultSettings()
	settings.Groups = map[string]GroupSettings{"ru": settings.ForGroup("ru"), "world": settings.ForGroup("world")}
	if err := manager.ApplySettings(settings); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager.Configure(ctx, map[string][]string{"ru": {"shared", "reserve"}, "world": {"shared"}})
	if len(manager.workers["ru"].engine.paths) != 2 || len(manager.workers["world"].engine.paths) != 1 {
		t.Fatal("reserve/group paths not configured")
	}
	now := time.Now()
	for id, worker := range manager.workers {
		worker.engine.mu.Lock()
		for _, check := range worker.engine.settings.Checks {
			result := success
			if id == "world" {
				result = failure
			}
			for _, target := range check.Targets {
				worker.engine.record(seriesKey{"shared", check.Protocol, target}, now, result)
			}
		}
		worker.engine.mu.Unlock()
	}
	_, ru := manager.Snapshot("ru", []string{"shared", "reserve"})
	_, world := manager.Snapshot("world", []string{"shared"})
	if ru["shared"].Overall == nil || *ru["shared"].Overall != 100 || world["shared"].Overall == nil || *world["shared"].Overall != 0 || ru["reserve"].Overall != nil {
		t.Fatal(ru, world)
	}
	changed := settings.ForGroup("ru")
	changed.Checks[0].DNSName = "example.org"
	settings.Groups["ru"] = changed
	if err := manager.ApplySettings(settings); err != nil {
		t.Fatal(err)
	}
	_, ru = manager.Snapshot("ru", []string{"shared"})
	_, world = manager.Snapshot("world", []string{"shared"})
	if ru["shared"].Overall != nil || world["shared"].Overall == nil {
		t.Fatal("cross-group invalidation", ru, world)
	}
	manager.Configure(ctx, map[string][]string{"world": {"shared"}})
	if _, ok := manager.workers["ru"]; ok {
		t.Fatal("removed worker retained")
	}
}

// TestGroupWindowsExpireIndependently uses the same observation time under distinct group windows.
func TestGroupWindowsExpireIndependently(t *testing.T) {
	settings := DefaultSettings()
	short := settings.ForGroup("short")
	short.WindowMinutes = 1
	settings.Groups = map[string]GroupSettings{"short": short, "long": settings.ForGroup("long")}
	manager, err := NewGroupEngine(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplySettings(settings); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager.Configure(ctx, map[string][]string{"short": {"same"}, "long": {"same"}})
	for _, worker := range manager.workers {
		worker.engine.mu.Lock()
		worker.engine.started = time.Now().Add(-10 * time.Minute)
		for _, check := range worker.engine.settings.Checks {
			for _, target := range check.Targets {
				worker.engine.record(seriesKey{"same", check.Protocol, target}, time.Now().Add(-2*time.Minute), success)
			}
		}
		worker.engine.mu.Unlock()
	}
	_, shortScores := manager.Snapshot("short", []string{"same"})
	_, longScores := manager.Snapshot("long", []string{"same"})
	if shortScores["same"].Overall != nil || longScores["same"].Overall == nil || *longScores["same"].Overall != 100 {
		t.Fatal(shortScores, longScores)
	}
}
