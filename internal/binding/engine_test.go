package binding

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBindingTransaction exercises stale writes, failed live confirmation, rollback and a first confirmed change.
func TestBindingTransaction(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	if err := e.Apply(ctx, "com", "other", "ru"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if err := e.Apply(ctx, "missing", "fi", "ru"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	old, err := os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Fail the candidate's first live verification only; rollback must verify the prior files.
	verify := e.run
	failed := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == systemctl && len(args) == 2 && args[0] == "start" && args[1] == "hestia-smoke@fresh.service" && !failed {
			b, _ := os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
			if string(b) != string(old) {
				failed = true
				return errors.New("candidate rejected")
			}
		}
		return verify(ctx, name, args...)
	}
	if err := e.Apply(ctx, "com", "fi", "ru"); err == nil || !failed {
		t.Fatalf("unconfirmed change accepted: %v", err)
	}
	b, err := e.readSnapshot()
	if err != nil || string(b) != string(old) {
		t.Fatal("did not restore prior snapshot", err)
	}
	if err := e.Apply(ctx, "com", "fi", "ru"); err != nil {
		t.Fatalf("valid change: %v", err)
	}
	if err := e.Apply(ctx, "com", "fi", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale retry: %v", err)
	}
}

// TestBindingRollbackRestoresAWGSecretTree verifies the durable generation rollback includes connector secrets.
func TestBindingRollbackRestoresAWGSecretTree(t *testing.T) {
	e := testEngine(t)
	active := filepath.Join(e.dir, awgTreeName)
	writeTestAWGTree(t, active)
	original, err := os.ReadFile(filepath.Join(active, "conn", "profile.conf"))
	if err != nil {
		t.Fatal(err)
	}
	baseRun := e.run
	failed := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == python && args[1] == profile {
			if err := baseRun(ctx, name, args...); err != nil {
				return err
			}
			candidate := filepath.Join(args[4], awgTreeName, "conn", "profile.conf")
			data := []byte(strings.Replace(treeTestProfile, ":51820", ":51821", 1))
			if err := os.WriteFile(candidate, data, 0600); err != nil {
				return err
			}
			return nil
		}
		if name == systemctl && len(args) == 2 && args[0] == "start" && args[1] == "hestia-smoke@fresh.service" && !failed {
			failed = true
			return errors.New("candidate rejected")
		}
		return baseRun(ctx, name, args...)
	}
	if err := e.Apply(context.Background(), "com", "fi", "ru"); err == nil || !failed {
		t.Fatalf("unconfirmed connector generation was accepted: %v", err)
	}
	restored, err := os.ReadFile(filepath.Join(active, "conn", "profile.conf"))
	if err != nil || string(restored) != string(original) {
		t.Fatalf("previous AWG secret tree was not restored: %v", err)
	}
}

// testEngine creates a local profile and simulates only the external compiler and systemd operations.
func testEngine(t *testing.T) Engine {
	t.Helper()
	e := Engine{dir: t.TempDir(), snapshotGID: os.Getegid()}
	e.lock = filepath.Join(e.dir, "lock")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(e.lock, "")
	if err := os.Chmod(e.lock, 0640); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(e.dir, ".installer-managed"), "1\n")
	for _, name := range managedFiles {
		value := "old"
		if name == "profile.json" {
			value = `{"connectors":[]}`
		}
		write(filepath.Join(e.dir, name), value)
	}
	sample := func(group string) string {
		return `{"groups":[{"id":"fi"},{"id":"ru"}],"lists":[{"id":"com","group":"` + group + `","masks":["*.com"]}],"healthy":{}}`
	}
	write(filepath.Join(e.dir, "snapshot.json"), sample("fi"))
	if err := os.Chmod(filepath.Join(e.dir, "snapshot.json"), 0640); err != nil {
		t.Fatal(err)
	}
	writeTestDigests(t, e.dir)
	e.run = func(_ context.Context, name string, args ...string) error {
		if name == python && args[1] == profile {
			for _, file := range managedFiles {
				value := "new"
				if file == "profile.json" {
					value = `{"connectors":[]}`
				}
				write(filepath.Join(args[4], file), value)
			}
			write(filepath.Join(args[4], "snapshot.json"), sample(args[6]))
			writeTestDigests(t, args[4])
		}
		return nil
	}
	return e
}

// TestInterruptedBinding checks that candidate files stay hidden until offline restoration succeeds.
func TestInterruptedBinding(t *testing.T) {
	e := testEngine(t)
	interruptBinding(t, e)
	if _, err := e.readSnapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("read pending generation")
	}
	e.run = func(context.Context, string, ...string) error {
		t.Fatal("offline recovery called a service")
		return nil
	}
	if err := e.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	data, err := e.readSnapshot()
	if err != nil || checkChange(data, "com", "fi", "ru") != nil {
		t.Fatal("prior generation not restored", err)
	}
}

// TestBindingLocks checks that a concurrent update excludes snapshot reads and other writers.
func TestBindingLocks(t *testing.T) {
	e := testEngine(t)
	writer, err := e.acquire(true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := e.readSnapshot(); !errors.Is(err, ErrConflict) {
		t.Fatalf("shared read allowed: %v", err)
	}
	if err := e.Apply(context.Background(), "com", "fi", "ru"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second writer allowed: %v", err)
	}
}

// writeTestDigests records the checksums the installer would have stored for the fixture's two protected files.
func writeTestDigests(t *testing.T, dir string) {
	t.Helper()
	for _, pair := range [][2]string{{"profile.json", "profile-source.sha256"}, {"sing-box.json", "profile-backend.sha256"}} {
		data, err := os.ReadFile(filepath.Join(dir, pair[0]))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, pair[1]), []byte(fmt.Sprintf("%x\n", sha256.Sum256(data))), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// interruptBinding leaves a different installed generation and durable journal as if the helper died before commit.
func interruptBinding(t *testing.T, e Engine) {
	t.Helper()
	stage, err := os.MkdirTemp(e.dir, "stage-")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.run(context.Background(), python, "-I", profile, "--rebind", e.dir, stage, "com", "ru"); err != nil {
		t.Fatal(err)
	}
	if err := e.publishJournal(stage); err != nil {
		t.Fatal(err)
	}
	if err := e.installFiles(filepath.Join(e.dir, pending), false); err != nil {
		t.Fatal(err)
	}
}

// TestWatchPending checks recovery of an abandoned candidate once the helper's lock has been released.
func TestWatchPending(t *testing.T) {
	e := testEngine(t)
	lock, err := e.acquire(true)
	if err != nil {
		t.Fatal(err)
	}
	interruptBinding(t, e)
	called := []string{}
	e.run = func(_ context.Context, name string, args ...string) error {
		if name != systemctl {
			t.Errorf("unexpected recovery command: %s", name)
		}
		called = append(called, strings.Join(args, " "))
		return nil
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { result <- e.WatchPending(ctx) }()
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(called) != "[stop hestia.service hestia-sing-box.service start hestia-sing-box.service hestia.service start hestia-smoke@fresh.service]" {
		t.Fatalf("incorrect recovery operations: %v", called)
	}
	data, err := e.readSnapshot()
	if err != nil || checkChange(data, "com", "fi", "fi") != nil {
		t.Fatal("recovery did not restore original group", err)
	}
}

// TestUnsafeRecovery verifies that a corrupt journal stops services before any file can be restored with unsafe permissions.
func TestUnsafeRecovery(t *testing.T) {
	for _, damage := range []string{"journal-symlink", "previous-symlink", "file-symlink", "public-secret", "wrong-snapshot-mode", "missing-backup", "corrupt-digest", "valid-but-substituted-snapshot"} {
		t.Run(damage, func(t *testing.T) {
			e := testEngine(t)
			interruptBinding(t, e)
			journal := filepath.Join(e.dir, pending)
			previous := filepath.Join(journal, "previous")
			secret := filepath.Join(previous, "sing-box.json")
			var err error
			switch damage {
			case "journal-symlink", "previous-symlink", "file-symlink":
				path := map[string]string{"journal-symlink": journal, "previous-symlink": previous, "file-symlink": secret}[damage]
				if err = os.Rename(path, path+".save"); err == nil {
					err = os.Symlink(path+".save", path)
				}
			case "public-secret":
				err = os.Chmod(secret, 0644)
			case "wrong-snapshot-mode":
				err = os.Chmod(filepath.Join(previous, "snapshot.json"), 0600)
			case "missing-backup":
				err = os.Remove(filepath.Join(previous, "snapshot.json"))
			case "valid-but-substituted-snapshot":
				// Both generations are valid; only the saved digest identifies the committed one.
				var candidate []byte
				candidate, err = os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
				if err == nil {
					err = os.WriteFile(filepath.Join(previous, "snapshot.json"), candidate, 0640)
				}
			case "corrupt-digest":
				err = os.WriteFile(filepath.Join(previous, "profile-backend.sha256"), []byte("bad"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			stopped := false
			e.run = func(_ context.Context, name string, args ...string) error {
				if name != systemctl || args[0] != "stop" {
					t.Fatalf("unexpected service action: %s %q", name, args)
				}
				stopped = true
				return nil
			}
			if err := e.WatchPending(context.Background()); err == nil || !stopped {
				t.Fatalf("unsafe recovery: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(e.dir, "profile.json"))
			if err != nil || string(data) != `{"connectors":[]}` {
				t.Fatal("partial restoration", err)
			}
			if _, err := e.readSnapshot(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("journal was retired: %v", err)
			}
		})
	}
}

// TestWatchWaitsForWriter checks that supervision leaves an active writer alone and can cancel a wait.
func TestWatchWaitsForWriter(t *testing.T) {
	e := testEngine(t)
	lock, err := e.acquire(true)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := e.WatchPending(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("watch did not wait for writer: %v", err)
	}
}

// TestWatchRequired checks that an installation without active recovery supervision cannot publish a candidate.
func TestWatchRequired(t *testing.T) {
	e := testEngine(t)
	run := e.run
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == systemctl && args[0] == "is-active" {
			return errors.New("inactive")
		}
		return run(ctx, name, args...)
	}
	if err := e.Apply(context.Background(), "com", "fi", "ru"); err == nil {
		t.Fatal("accepted unsupervised change")
	}
	data, err := e.readSnapshot()
	if err != nil || checkChange(data, "com", "fi", "fi") != nil {
		t.Fatal("failed early check changed snapshot", err)
	}
}
