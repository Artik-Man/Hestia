package dnspolicy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// TestStoreDurableMembership verifies default migration, normalization, independent lists, retry and restart.
func TestStoreDurableMembership(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "dns", "policy.json")}
	initial, err := store.Read()
	if err != nil || initial.Revision != 0 || initial.Policy.Manual == nil || initial.Policy.Exclusions == nil {
		t.Fatalf("missing file: %+v, %v", initial, err)
	}
	next := initial.Policy
	next.Manual = []string{"Warm.Example."}
	next.Exclusions = []string{"WARM.example"}
	first, err := store.Apply(initial.Revision, next)
	if err != nil || first.Revision != 1 || !slices.Equal(first.Policy.Manual, []string{"warm.example"}) {
		t.Fatalf("first update: %+v, %v", first, err)
	}
	restarted, err := (Store{Path: store.Path}).Read()
	if err != nil || restarted.Revision != 1 || !slices.Equal(restarted.Policy.Exclusions, first.Policy.Manual) {
		t.Fatalf("restart: %+v, %v", restarted, err)
	}
	if _, err := store.Apply(0, next); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	if repeated, err := store.Apply(1, next); err != nil || repeated.Revision != 1 {
		t.Fatalf("equivalent update: %+v, %v", repeated, err)
	}
}

// TestStoreRejectsInvalid verifies rejected mutations leave the original durable revision intact.
func TestStoreRejectsInvalid(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "policy.json")}
	initial, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{nil, {"*.example"}, {"x.example", "X.EXAMPLE."}, {"bad..example"}, {"127.0.0.1"}, {"x.example.."}} {
		next := initial.Policy
		next.Manual = names
		if _, err := store.Apply(0, next); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid names %v: %v", names, err)
		}
	}
	next := initial.Policy
	next.Settings.ServeStale = true
	next.Settings.StaleWindowSeconds = next.Settings.RetentionSeconds + 1
	if _, err := store.Apply(0, next); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted unsafe stale window: %v", err)
	}
	if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected persisted state: %v", err)
	}
}

// TestStoreConcurrentCAS verifies separate writers cannot commit different updates at the same revision.
func TestStoreConcurrentCAS(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "policy.json")}
	initial, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, name := range []string{"one.example", "two.example"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			next := initial.Policy
			next.Manual = []string{name}
			_, err := store.Apply(0, next)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("successful=%d, conflicted=%d", success, conflict)
	}
}

// TestStoreCorruption verifies malformed on-disk state cannot be replaced using a default revision.
func TestStoreCorruption(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "policy.json")}
	initial, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.Path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil || errors.Is(err, ErrInvalid) {
		t.Fatalf("malformed file must report storage failure: %v", err)
	}
	if _, err := store.Apply(0, initial.Policy); err == nil {
		t.Fatal("malformed file overwritten")
	}
}

// TestStoreRequiredFlags rejects absent and null disk values even when zero is valid in the API.
func TestStoreRequiredFlags(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "policy.json")}
	for _, field := range []string{"", `"serveStale":null,`} {
		data := `{"revision":1,"policy":{"manual":[],"exclusions":[],"settings":{"retentionSeconds":0,` + field + `"staleWindowSeconds":0,"automaticEnabled":true,"threshold":5,"windowHours":24,"intervalMinutes":10}}}`
		if err := os.WriteFile(store.Path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("accepted incomplete settings")
		}
	}
}
