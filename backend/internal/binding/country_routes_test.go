package binding

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestCountryMapMigrationAndRollback exercises the real profile compiler, legacy migration and rejection of an invalid candidate.
func TestCountryMapMigrationAndRollback(t *testing.T) {
	e := testEngine(t)
	e.countryMapPath = filepath.Join(t.TempDir(), "policy.json")
	script, err := filepath.Abs("../../../deploy/profile.py")
	if err != nil {
		t.Fatal(err)
	}
	deployDir := filepath.Dir(script)
	for _, file := range []string{"snapshot", "sing-box", "profile"} {
		source, err := os.ReadFile(filepath.Join(deployDir, "scheme3", "guest-"+file+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(e.dir, file+".json"), source, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTestDigests(t, e.dir)
	ctx := context.Background()
	initial, err := e.ReadCountryMap()
	if err != nil {
		t.Fatal(err)
	}
	restarts := 0
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == python && args[1] == profile {
			cmd := exec.CommandContext(ctx, "python3", append([]string{"-I", script}, args[2:]...)...)
			if text, err := cmd.CombinedOutput(); err != nil {
				t.Logf("compiler: %s", text)
				return err
			}
		}
		if name == systemctl && slices.Contains(args, smokeFresh) {
			restarts++
		}
		return nil
	}
	if err := e.MigrateCountryMap(ctx); err != nil {
		t.Fatal(err)
	}
	applied, err := e.ReadCountryMap()
	if err != nil || applied.Version == initial.Version || applied.Enabled || restarts != 1 {
		t.Fatalf("migration readback: %#v (restarts %d): %v", applied, restarts, err)
	}
	if err := e.MigrateCountryMap(ctx); err != nil || restarts != 1 {
		t.Fatalf("migration replayed: restarts %d, err %v", restarts, err)
	}
	if _, err := e.ApplyCountryMap(ctx, initial); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale edit: %v", err)
	}
	if _, err := e.ApplyCountryMap(ctx, applied); err != nil || restarts != 1 {
		t.Fatalf("same edit restarted: %d, %v", restarts, err)
	}
	// A missing local dataset must reject activation. The live policy and routing generation retain their versions.
	applied.Enabled = true
	existingRun := e.run
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == python {
			return errors.New("country database unavailable")
		}
		return existingRun(ctx, name, args...)
	}
	if _, err = e.ApplyCountryMap(ctx, applied); err == nil {
		t.Fatal("accepted missing country database")
	}
	after, err := e.ReadCountryMap()
	if err != nil || after.Enabled || after.Version != applied.Version || restarts != 1 {
		t.Fatalf("failed save changed live policy: %#v, %v", after, err)
	}
}

// TestUnopenedCountryMapMigration activates sniffing for managed domain lists even before a panel visit.
func TestUnopenedCountryMapMigration(t *testing.T) {
	e := testEngine(t)
	e.countryMapPath = filepath.Join(t.TempDir(), "absent.json")
	script, err := filepath.Abs("../../../deploy/profile.py")
	if err != nil {
		t.Fatal(err)
	}
	base := mustReadTestFile(t, filepath.Join(filepath.Dir(script), "scheme3", "guest-profile.json"))
	base = bytes.Replace(base, []byte(`"lists": []`), []byte(`"lists": [{"id":"local","group":"default","masks":["*.ru"]}]`), 1)
	src := filepath.Join(e.dir, "profile.json")
	if err := os.WriteFile(src, base, 0600); err != nil {
		t.Fatal(err)
	}
	compiled := t.TempDir()
	if out, err := exec.Command("python3", "-I", script, src, compiled, e.dir).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	for _, name := range []string{"snapshot.json", "sing-box.json"} {
		if err := os.WriteFile(filepath.Join(e.dir, name), mustReadTestFile(t, filepath.Join(compiled, name)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTestDigests(t, e.dir)
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == python && args[1] == profile {
			return exec.CommandContext(ctx, "python3", append([]string{"-I", script}, args[2:]...)...).Run()
		}
		return nil
	}
	if err := e.MigrateCountryMap(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := e.ReadCountryMap()
	if err != nil || got.Enabled || got.Assignments["RU"] != "default" || !bytes.Contains(mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json")), []byte(`"sniff"`)) {
		t.Fatalf("migration lost initial policy or domain recognition: %v", err)
	}
}
