// Package binding transactionally applies routing changes in the managed gateway profile.
package binding

import (
	"context"
	"errors"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/platform"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"github.com/Artik-Man/Hestia/internal/storage"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/services"
)

var (
	ErrNotFound    = errors.New("unknown domain list or group")
	ErrConflict    = errors.New("binding has changed or another operation is in progress")
	ErrUnavailable = errors.New("managed routing configuration unavailable")
)

type rolledBackActivationError struct {
	cause error
}

// Error returns the original activation failure after the transaction has restored its previous generation.
func (e rolledBackActivationError) Error() string { return e.cause.Error() }

// Unwrap preserves the activation cause for typed recovery decisions after confirmed rollback.
func (e rolledBackActivationError) Unwrap() error { return e.cause }

type transactionStageError struct {
	stage string
	cause error
}

// Error returns the underlying transaction error without exposing the diagnostic stage as an error message.
func (e transactionStageError) Error() string { return e.cause.Error() }

// Unwrap preserves error classification for callers that handle a transaction failure.
func (e transactionStageError) Unwrap() error { return e.cause }

// TransactionFailureStage reports a fixed, non-sensitive transaction stage for operational diagnostics.
func TransactionFailureStage(err error) string {
	var failure transactionStageError
	if errors.As(err, &failure) {
		return failure.stage
	}
	return ""
}

// TransactionFailureCode reports a fixed, non-sensitive category for the transaction's underlying failure.
func TransactionFailureCode(err error) string {
	var failure transactionStageError
	if !errors.As(err, &failure) || failure.cause == nil {
		return ""
	}
	cause := failure.cause.Error()
	switch {
	case strings.Contains(cause, "AWG route table contains an unowned IPv4 route"):
		return "route-table-unowned-ipv4"
	case strings.Contains(cause, "AWG route table contains an unowned IPv6 route"):
		return "route-table-unowned-ipv6"
	case strings.Contains(cause, "AWG rule priority contains an unowned rule"):
		return "route-rule-unowned"
	case strings.Contains(cause, "AWG packet mark is used by an unowned rule"):
		return "route-mark-unowned"
	case strings.Contains(cause, "AWG route teardown incomplete"):
		return "route-teardown-incomplete"
	case strings.Contains(cause, "managed service operation failed: controller") || strings.Contains(cause, "managed service role unavailable: controller"):
		return "service-controller"
	case strings.Contains(cause, "managed service operation failed: router") || strings.Contains(cause, "managed service role unavailable: router"):
		return "service-router"
	case strings.Contains(cause, "managed service operation failed: awg") || strings.Contains(cause, "managed service role unavailable: awg"):
		return "service-awg"
	case errors.Is(failure.cause, ErrAWGRuntimeUnconfirmed):
		return "runtime-unconfirmed"
	default:
		return "transaction-failed"
	}
}

const (
	pending = ".binding-pending"
)

var (
	awgReady = storage.Installed().AWGReady
)

var managedFiles = []string{"profile.json", "profile-source.sha256", "sing-box.json", "profile-backend.sha256", "snapshot.json"}

// Engine operates on fixed trusted installation paths. Its commands take structured arguments without a shell.
type Engine struct {
	compiler       profileexec.CompilerAPI
	services       services.Manager
	dir, lock      string
	countryMapPath string
	snapshotGID    int
	retryAWGID     string
	run            func(context.Context, string, ...string) error
	unitCheck      func() (bool, error)
	readyWait      func(context.Context, string) error
	guardCheck     func(context.Context, string, int) error
}

// Installed returns the engine with storage and service adapters selected for the current platform build.
func Installed() Engine {
	gid := -1
	if group, err := user.LookupGroup("hestia-snapshot"); err == nil {
		if value, err := strconv.Atoi(group.Gid); err == nil {
			gid = value
		}
	}
	return Engine{countryMapPath: storage.Installed().CountryPolicy, dir: storage.Installed().Config, lock: storage.Installed().InstallLock, snapshotGID: gid, run: runCommand, services: platform.Services(nil), compiler: profileexec.Installed{}}
}

// runCommand executes one bounded local command and keeps private command output out of errors.
func runCommand(ctx context.Context, name string, args ...string) error {
	return profileexec.RunCommand(ctx, name, args...)
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
	return e.serviceManager().Start(ctx, services.Service{Kind: services.SmokeFresh})
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
		return e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.Rebind, Source: e.dir, Stage: dir, ID: id, Target: target})
	}
	return e.apply(ctx, stageBinding, check, expected == target)
}

// apply checks the operation's precondition under the installer lock, stages and validates the proposed change,
// and runs a supervised transaction. Even a no-op requires confirmation of the current services.
func (e Engine) apply(ctx context.Context, prepare func(string) error, check func([]byte, bool) error, noChange bool) error {
	return e.applyWithNoChangeCheck(ctx, prepare, check, noChange, nil)
}

// applyWithNoChangeCheck skips an identical request only when its prepared route needs no repair.
func (e Engine) applyWithNoChangeCheck(
	ctx context.Context,
	prepare func(string) error,
	check func([]byte, bool) error,
	noChange bool,
	canSkip func(string) (bool, error),
) error {
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := e.validateInstallation(); err != nil {
		return transactionStageError{stage: "installation-validation", cause: err}
	}
	if err := e.recoverIfPending(ctx, true); err != nil {
		return transactionStageError{stage: "pending-recovery", cause: err}
	}
	snapshot, err := os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
	if err != nil {
		return transactionStageError{stage: "snapshot-read", cause: ErrUnavailable}
	}
	if err := check(snapshot, false); err != nil {
		return transactionStageError{stage: "current-snapshot-check", cause: err}
	}
	if err := e.validateGeneration(e.dir, true); err != nil {
		return transactionStageError{stage: "current-generation-validation", cause: err}
	}
	stage, err := os.MkdirTemp(e.dir, ".binding-stage-")
	if err != nil {
		return transactionStageError{stage: "stage-directory", cause: err}
	}
	defer os.RemoveAll(stage)
	if err := e.stageAWGTree(stage); err != nil {
		return transactionStageError{stage: "connector-tree-copy", cause: err}
	}
	if err := prepare(stage); err != nil {
		return transactionStageError{stage: "candidate-preparation", cause: fmt.Errorf("candidate preparation failed: %w", err)}
	}
	next, err := os.ReadFile(filepath.Join(stage, "snapshot.json"))
	if err != nil {
		return transactionStageError{stage: "candidate-snapshot-read", cause: ErrUnavailable}
	}
	if err := check(next, true); err != nil {
		return transactionStageError{stage: "candidate-snapshot-check", cause: fmt.Errorf("candidate snapshot is invalid: %w", err)}
	}
	if err := e.profileCompiler().CheckBackend(ctx, filepath.Join(stage, "sing-box.json")); err != nil {
		return transactionStageError{stage: "candidate-backend-check", cause: err}
	}
	// The current watcher may have been running longer than its retained journal.
	if err := e.serviceManager().Start(ctx, services.Service{Kind: services.SmokeCurrent}); err != nil {
		return transactionStageError{stage: "current-generation-smoke", cause: err}
	}
	if noChange {
		if canSkip == nil {
			return nil
		}
		skip, err := canSkip(stage)
		if err != nil {
			return transactionStageError{stage: "no-change-check", cause: err}
		}
		if skip {
			return nil
		}
	}
	if err := e.requireServiceActive(ctx, services.BindingWatch); err != nil {
		return transactionStageError{stage: "binding-watch-check", cause: err}
	}
	if err := e.publishJournal(stage); err != nil {
		return transactionStageError{stage: "journal-publish", cause: err}
	}
	if err := e.activate(ctx); err != nil {
		// A disconnected client cannot cancel rollback of a transaction already visible on disk.
		rollback, cancel := context.WithTimeout(context.Background(), AWGActivationLimit)
		defer cancel()
		if recoveryErr := e.recoverIfPending(rollback, true); recoveryErr != nil {
			return transactionStageError{stage: "activation-and-rollback", cause: errors.Join(err, recoveryErr)}
		}
		return transactionStageError{stage: "activation", cause: rolledBackActivationError{cause: err}}
	}
	return nil
}

// activate publishes verified files with the necessary services drained, then confirms and commits the candidate.
func (e Engine) activate(ctx context.Context) error {
	journal := filepath.Join(e.dir, pending)
	routingOnly, err := e.routingOnly(journal)
	if err != nil {
		return err
	}
	plan, err := e.stop(ctx, journal, routingOnly)
	if err != nil {
		return err
	}
	if err := e.installFiles(journal, routingOnly); err != nil {
		return err
	}
	if err := e.startVerified(ctx, plan); err != nil {
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
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Lstat(filepath.Join(e.dir, ".installer-managed")); errors.Is(markerErr, os.ErrNotExist) {
			return nil
		} else if markerErr != nil {
			return ErrUnavailable
		}
	} else if err != nil {
		return ErrUnavailable
	}
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := e.validateInstallation(); err != nil {
		return err
	}
	if err := e.recoverIfPending(ctx, false); err != nil {
		return err
	}
	if err := e.validateGeneration(e.dir, true); err != nil {
		return err
	}
	return e.startAWGForBoot(ctx)
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
	routingOnly, modeErr := e.routingOnly(journal)
	var plan runtimePlan
	if online {
		// A damaged journal cannot prove that its previous generation is safe to serve.
		plan, err = e.stop(ctx, journal, routingOnly)
		if err != nil {
			return errors.Join(modeErr, err)
		}
	}
	if modeErr != nil {
		return modeErr
	}
	if err := e.installFiles(filepath.Join(journal, "previous"), routingOnly); err != nil {
		return err
	}
	if online {
		if err := e.startVerified(ctx, plan); err != nil {
			stop, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			_, stopErr := e.stop(stop, journal, routingOnly)
			return errors.Join(err, stopErr)
		}
	}
	return e.retireJournal()
}
