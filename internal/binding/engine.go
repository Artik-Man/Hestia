// Package binding transactionally applies routing changes in the managed gateway profile.
package binding

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Artik-Man/Hestia/internal/controller"
)

var (
	ErrNotFound    = errors.New("unknown domain list or group")
	ErrConflict    = errors.New("binding has changed or another operation is in progress")
	ErrUnavailable = errors.New("managed routing configuration unavailable")
)

const (
	python    = "/usr/bin/python3"
	profile   = "/usr/local/lib/hestia/profile.py"
	smoke     = "/usr/local/lib/hestia/smoke.py"
	backend   = "/usr/local/lib/hestia/sing-box"
	systemctl = "/usr/bin/systemctl"
	watcher   = "hestia.service"
	router    = "hestia-sing-box.service"
	pending   = ".binding-pending"
)

var managedFiles = []string{"profile.json", "profile-source.sha256", "sing-box.json", "profile-backend.sha256", "snapshot.json"}

// Engine operates on fixed trusted installation paths. Its commands take structured arguments without a shell.
type Engine struct {
	dir, lock   string
	snapshotGID int
	run         func(context.Context, string, ...string) error
}

// Installed returns the engine for the installer-managed Debian gateway.
func Installed() Engine {
	gid := -1
	if group, err := user.LookupGroup("hestia-snapshot"); err == nil {
		if value, err := strconv.Atoi(group.Gid); err == nil {
			gid = value
		}
	}
	return Engine{dir: "/etc/hestia", lock: "/run/hestia-install.lock", snapshotGID: gid, run: runCommand}
}

// runCommand executes one bounded local command and keeps private command output out of errors.
func runCommand(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return nil
}

// checkChange checks the expected list binding and confirms that the target exists or is unassigned.
func checkChange(data []byte, id, expected, target string) error {
	cfg, err := controller.CheckSnapshot(data)
	if err != nil {
		return ErrUnavailable
	}
	for _, list := range cfg.Lists {
		if list.ID != id {
			continue
		}
		if list.Group != expected {
			return ErrConflict
		}
		if target == "" {
			return nil
		}
		for _, g := range cfg.Groups {
			if g.ID == target {
				return nil
			}
		}
		return ErrNotFound
	}
	return ErrNotFound
}

// verify requires the running backend's credential and the current watcher's selector confirmations to match the installed files.
func (e Engine) verify(ctx context.Context) error {
	return e.run(ctx, python, "-I", smoke)
}

// stop waits until both routing services are stopped so the watcher cannot observe a partially published generation.
func (e Engine) stop(ctx context.Context) error {
	return e.run(ctx, systemctl, "stop", watcher, router)
}

// startVerified starts the managed backend and a fresh watcher and waits for confirmation from both.
func (e Engine) startVerified(ctx context.Context) error {
	if err := e.run(ctx, systemctl, "start", router, watcher); err != nil {
		return err
	}
	return e.verify(ctx)
}

// Apply serializes updates with the installer, rejects stale bindings, and returns success only after live verification.
// An interrupted transaction retains a private rollback journal. The next write or offline recovery restores it.
func (e Engine) Apply(ctx context.Context, id, expected, target string) error {
	check := func(data []byte, staged bool) error {
		if staged {
			return checkChange(data, id, target, target)
		}
		return checkChange(data, id, expected, target)
	}
	stageBinding := func(dir string) error {
		return e.run(ctx, python, "-I", profile, "--rebind", e.dir, dir, id, target)
	}
	return e.apply(ctx, stageBinding, check, expected == target)
}

// apply checks the operation's precondition under the installer lock, stages and validates the proposed change,
// and runs a supervised transaction. Even a no-op requires confirmation of the current services.
func (e Engine) apply(ctx context.Context, prepare func(string) error, check func([]byte, bool) error, noChange bool) error {
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := e.validateInstallation(); err != nil {
		return err
	}
	if err := e.recoverIfPending(ctx, true); err != nil {
		return err
	}
	snapshot, err := os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
	if err != nil {
		return ErrUnavailable
	}
	if err := check(snapshot, false); err != nil {
		return err
	}
	if err := e.validateGeneration(e.dir, true); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(e.dir, ".binding-stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := prepare(stage); err != nil {
		return err
	}
	next, err := os.ReadFile(filepath.Join(stage, "snapshot.json"))
	if err != nil || check(next, true) != nil {
		return ErrUnavailable
	}
	if err := e.run(ctx, backend, "check", "-c", filepath.Join(stage, "sing-box.json")); err != nil {
		return err
	}
	// The current watcher may have been running longer than its retained journal.
	if err := e.run(ctx, python, "-I", smoke, "--current"); err != nil {
		return err
	}
	if noChange {
		return nil
	}
	if err := e.run(ctx, systemctl, "is-active", "--quiet", "hestia-binding-watch.path"); err != nil {
		return err
	}
	if err := e.publishJournal(stage); err != nil {
		return err
	}
	if err := e.activate(ctx); err != nil {
		// A disconnected client cannot cancel rollback of a transaction already visible on disk.
		rollback, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		return errors.Join(err, e.recoverIfPending(rollback, true))
	}
	return nil
}

// activate replaces the installed files only while routing is stopped, then confirms and commits the candidate.
func (e Engine) activate(ctx context.Context) error {
	journal := filepath.Join(e.dir, pending)
	if err := e.stop(ctx); err != nil {
		return err
	}
	if err := e.installFiles(journal); err != nil {
		return err
	}
	if err := e.startVerified(ctx); err != nil {
		return err
	}
	return e.retireJournal()
}

// WatchPending waits for the writer to exit and independently restores any generation it left unconfirmed.
// A successful writer already retired its journal and the watchdog then leaves the running services alone.
func (e Engine) WatchPending(ctx context.Context) error {
	for {
		lock, err := e.acquire(true)
		if err == nil {
			defer lock.Close()
			if err := e.validateInstallation(); err != nil {
				return err
			}
			return e.recoverIfPending(ctx, true)
		}
		if !errors.Is(err, ErrConflict) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Recover restores files from an interrupted write before systemd starts either routing service.
// It must only run offline, when both services are stopped.
func (e Engine) Recover(ctx context.Context) error {
	// The installer may already hold the lock while bootstrapping the recovery unit.
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := e.validateInstallation(); err != nil {
		return err
	}
	return e.recoverIfPending(ctx, false)
}

// recoverIfPending restores every saved file under the exclusive lock and retains the journal on failure.
// Online recovery also restarts and verifies the prior generation, stopping services if it cannot be verified.
func (e Engine) recoverIfPending(ctx context.Context, online bool) error {
	journal := filepath.Join(e.dir, pending)
	_, err := os.Lstat(journal)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if online {
		if err := e.stop(ctx); err != nil {
			return err
		}
	}
	if err := e.installFiles(filepath.Join(journal, "previous")); err != nil {
		return err
	}
	if online {
		if err := e.startVerified(ctx); err != nil {
			stop, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			return errors.Join(err, e.stop(stop))
		}
	}
	return e.retireJournal()
}
