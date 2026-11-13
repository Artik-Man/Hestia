package binding

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Artik-Man/Hestia/internal/controller"
)

// TestSetCPUProfilingOnlyChangesPprof verifies transactional enable/disable preserves the entire routing snapshot and backend.
func TestSetCPUProfilingOnlyChangesPprof(t *testing.T) {
	e := managedConnectorTestEngine(t)
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(e.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	beforeSnapshot, beforeBackend := read("snapshot.json"), read("sing-box.json")
	beforeRoute, err := controller.CheckSnapshot(beforeSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	beforeBackendWithoutPprof, enabled, err := withoutCPUProfile(beforeBackend)
	if err != nil || enabled {
		t.Fatalf("baseline unexpectedly has pprof enabled: %v", err)
	}
	if err := e.SetCPUProfiling(context.Background(), true); err != nil {
		t.Fatalf("enable CPU profiling: %v", err)
	}
	profile, err := readStoredProfile(e.dir)
	if err != nil || profile.Diagnostics == nil || !profile.Diagnostics.CPUPprof {
		t.Fatalf("profile did not record diagnostics setting: %#v, %v", profile.Diagnostics, err)
	}
	if !reflect.DeepEqual(beforeRoute, mustCheckSnapshot(t, read("snapshot.json"))) {
		t.Fatal("enabling pprof changed controller routing snapshot")
	}
	withPprof := read("sing-box.json")
	withoutPprof, enabled, err := withoutCPUProfile(withPprof)
	if err != nil || !enabled || !reflect.DeepEqual(beforeBackendWithoutPprof, withoutPprof) {
		t.Fatalf("enabling pprof changed unrelated backend settings: enabled=%v error=%v", enabled, err)
	}
	if err := e.SetCPUProfiling(context.Background(), false); err != nil {
		t.Fatalf("disable CPU profiling: %v", err)
	}
	profile, err = readStoredProfile(e.dir)
	if err != nil || profile.Diagnostics != nil {
		t.Fatalf("profile retained diagnostics after disable: %#v, %v", profile.Diagnostics, err)
	}
	if !reflect.DeepEqual(beforeRoute, mustCheckSnapshot(t, read("snapshot.json"))) {
		t.Fatal("disabling pprof changed controller routing snapshot")
	}
	if !reflect.DeepEqual(beforeBackendWithoutPprof, mustDecodeBackend(t, read("sing-box.json"))) {
		t.Fatal("disabling pprof did not restore the original backend")
	}
}

// TestSetCPUProfilingPreservesCountryMap verifies the diagnostics transaction retains the optional country policy.
func TestSetCPUProfilingPreservesCountryMap(t *testing.T) {
	e := managedConnectorTestEngine(t)
	e.countryMapPath = filepath.Join(t.TempDir(), "country-map.json")
	if _, err := e.ReadCountryMap(); err != nil {
		t.Fatalf("initialize country map policy: %v", err)
	}
	if err := e.MigrateCountryMap(context.Background()); err != nil {
		t.Fatalf("initialize country map fixture: %v", err)
	}
	before, err := readStoredProfile(e.dir)
	if err != nil || before.CountryMap == nil {
		t.Fatalf("fixture has no country map: %#v, %v", before.CountryMap, err)
	}
	if err := e.SetCPUProfiling(context.Background(), true); err != nil {
		t.Fatalf("enable CPU profiling with country map: %v", err)
	}
	enabled, err := readStoredProfile(e.dir)
	if err != nil || !reflect.DeepEqual(enabled.CountryMap, before.CountryMap) {
		t.Fatalf("enable changed country map: %#v, %v", enabled.CountryMap, err)
	}
	if err := e.SetCPUProfiling(context.Background(), false); err != nil {
		t.Fatalf("disable CPU profiling with country map: %v", err)
	}
	disabled, err := readStoredProfile(e.dir)
	if err != nil || !reflect.DeepEqual(disabled.CountryMap, before.CountryMap) {
		t.Fatalf("disable changed country map: %#v, %v", disabled.CountryMap, err)
	}
}

// mustCheckSnapshot validates and decodes one test snapshot or fails the current test.
func mustCheckSnapshot(t *testing.T, data []byte) controller.Config {
	t.Helper()
	config, err := controller.CheckSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// mustDecodeBackend parses one test backend to a semantic JSON value or fails the current test.
func mustDecodeBackend(t *testing.T, data []byte) any {
	t.Helper()
	backend, _, err := withoutCPUProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	return backend
}
