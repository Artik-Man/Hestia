package binding

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestDomainListJournalRecovery verifies that a fresh watchdog preserves the running connector and its private files for a list edit, while older journals still take the full recovery path.
func TestDomainListJournalRecovery(t *testing.T) {
	for _, marked := range []bool{true, false} {
		label := "legacy"
		if marked {
			label = "domain-list"
		}
		t.Run(label, func(t *testing.T) {
			e := testEngine(t)
			e.unitCheck = func() (bool, error) { return true, nil }
			active := filepath.Join(e.dir, awgTreeName)
			writeTestAWGTree(t, active)
			secret := filepath.Join(active, "conn", "profile.conf")
			original, err := os.Stat(secret)
			if err != nil {
				t.Fatal(err)
			}
			stage, err := os.MkdirTemp(e.dir, "stage-")
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := e.stageAWGTree(stage); err != nil {
				t.Fatal(err)
			}
			if err := e.run(ctx, python, "-I", profile, "--rebind", e.dir, stage, "com", "ru"); err != nil {
				t.Fatal(err)
			}
			if marked {
				if err := os.WriteFile(filepath.Join(stage, "routing-only"), []byte("1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.publishJournal(stage); err != nil {
				t.Fatal(err)
			}
			// Reproduce a writer lost after replacing the snapshot but before its commit.
			if err := os.WriteFile(filepath.Join(e.dir, "snapshot.json"), mustReadTestFile(t, filepath.Join(e.dir, pending, "snapshot.json")), 0640); err != nil {
				t.Fatal(err)
			}
			touchedAWG := false
			verified := false
			e.run = func(_ context.Context, name string, args ...string) error {
				if name == systemctl {
					touchedAWG = touchedAWG || strings.Contains(strings.Join(args, " "), "hestia-awg")
					verified = verified || slices.Contains(args, smokeFresh)
				}
				return nil
			}
			if err := e.WatchPending(ctx); err != nil {
				t.Fatal(err)
			}
			restored, err := e.readSnapshot()
			if err != nil || checkChange(restored, "com", "fi", "") != nil {
				t.Fatal("committed list was not restored", err)
			}
			info, err := os.Stat(secret)
			if err != nil || os.SameFile(original, info) != marked || touchedAWG || !verified {
				t.Fatalf("unexpected recovery: preserved=%v awg=%v verified=%v err=%v", os.SameFile(original, info), touchedAWG, verified, err)
			}
		})
	}
}
