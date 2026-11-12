// Package profileexec defines typed operations against the installed profile compiler and backend validator.
package profileexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	commandTimeout = 20 * time.Second
	// backendCheckTimeout bounds candidate validation while the installed backend remains active on a loaded KN-1012.
	backendCheckTimeout  = 10 * time.Minute
	maxDiagnosticOutput  = 384
	maxDiagnosticMessage = 1200
)

// Operation selects one supported profile transformation.
type Operation uint8

const (
	Validate Operation = iota + 1
	Rebind
	Reorder
	CountryMap
	SaveList
	DeleteList
	MoveExit
	CreateGroup
	RenameGroup
	DeleteGroup
	Compile
	KeeneticIngress
)

// Request carries semantic transformation inputs; Source and Stage are trusted transaction directories.
type Request struct {
	Operation                                      Operation
	Source, Stage, ID, Target, Name, ExpectedGroup string
	UplinkDevice                                   string
	Priority                                       int
	PreserveWireguard                              bool
	Enabled                                        bool
}

// CompilerAPI is the platform boundary used by the transaction coordinator.
type CompilerAPI interface {
	Apply(context.Context, Request) error
	CheckBackend(context.Context, string) error
}

// Installed invokes fixed Linux programs; Run is an isolated command-observation seam.
type Installed struct {
	Run func(context.Context, string, ...string) error
}

// RunCommand runs a bounded command and returns safe, bounded process diagnostics on failure.
// It is adapter infrastructure, not an application operation API.
func RunCommand(ctx context.Context, name string, args ...string) error {
	return runCommand(ctx, name, commandTimeout, args...)
}

// runCommand executes one fixed helper while retaining bounded output and process termination details.
func runCommand(parent context.Context, name string, timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	started := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + CommandPath, "LANG=C"}
	stdout, stderr := &boundedBuffer{}, &boundedBuffer{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return newCommandFailure(commandRole(name), time.Since(started), ctx.Err(), err, stdout, stderr)
	}
	return nil
}

// commandRole maps only known helper paths to fixed diagnostic labels.
func commandRole(name string) string {
	switch filepath.Base(name) {
	case filepath.Base(Python):
		return "profile-compiler"
	case filepath.Base(Backend), "ld-linux-aarch64.so.1":
		return "backend-validator"
	default:
		return "profile-helper"
	}
}

// boundedBuffer caps captured child output while still consuming bytes written after the cap.
type boundedBuffer struct {
	bytes.Buffer
	truncated bool
}

// Write retains at most maxDiagnosticOutput bytes and reports truncation without stopping the child process.
func (b *boundedBuffer) Write(data []byte) (int, error) {
	remaining := maxDiagnosticOutput - b.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = b.Buffer.Write(data[:remaining])
		} else {
			_, _ = b.Buffer.Write(data)
		}
	}
	if len(data) > remaining {
		b.truncated = true
	}
	return len(data), nil
}

// commandFailure preserves process termination metadata without retaining arbitrary child text.
type commandFailure struct {
	role       string
	elapsed    time.Duration
	timedOut   bool
	exitCode   int
	signal     string
	launchErr  bool
	stdoutLen  int
	stderrLen  int
	stderrKind string
	stdoutCut  bool
	stderrCut  bool
	cause      error
}

// Error returns a safe, bounded description of one helper process failure.
func (e commandFailure) Error() string {
	status := "failed"
	switch {
	case e.launchErr:
		status = "could not start"
	case e.timedOut:
		status = "timed out"
	case e.signal != "":
		status = "terminated by signal " + e.signal
	case e.exitCode >= 0:
		status = fmt.Sprintf("exited with code %d", e.exitCode)
	}
	message := fmt.Sprintf("%s %s after %s", e.role, status, e.elapsed.Round(time.Millisecond))
	if e.stderrLen > 0 {
		message += fmt.Sprintf("; stderr %s withheld (%d bytes)", e.stderrKind, e.stderrLen)
	}
	if e.stdoutLen > 0 {
		message += fmt.Sprintf("; stdout withheld (%d bytes)", e.stdoutLen)
	}
	if e.stderrCut || e.stdoutCut {
		message += "; output truncated"
	}
	if len(message) > maxDiagnosticMessage {
		return message[:maxDiagnosticMessage] + "…"
	}
	return message
}

// Unwrap preserves standard process error inspection without including its path-bearing text in Error.
func (e commandFailure) Unwrap() error { return e.cause }

// newCommandFailure converts an exec error and bounded streams into a path-free diagnostic.
func newCommandFailure(role string, elapsed time.Duration, contextErr, err error, stdout, stderr *boundedBuffer) error {
	failure := commandFailure{role: role, elapsed: elapsed, exitCode: -1, cause: err}
	failure.timedOut = errors.Is(contextErr, context.DeadlineExceeded)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		failure.exitCode = exitErr.ExitCode()
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			failure.signal = status.Signal().String()
		}
	} else {
		var pathErr *os.PathError
		var execErr *exec.Error
		failure.launchErr = errors.As(err, &pathErr) || errors.As(err, &execErr)
	}
	if stdout != nil {
		failure.stdoutLen, failure.stdoutCut = stdout.Len(), stdout.truncated
	}
	if stderr != nil {
		failure.stderrLen, failure.stderrCut = stderr.Len(), stderr.truncated
		failure.stderrKind = stderrCategory(stderr.String())
	}
	return failure
}

// stderrCategory classifies child output without retaining or logging any of its content.
func stderrCategory(output string) string {
	lower := strings.ToLower(output)
	if strings.Contains(lower, "token") || strings.Contains(lower, "password") ||
		strings.Contains(lower, "secret") || strings.Contains(lower, "authorization") ||
		strings.Contains(lower, "private key") || strings.Contains(lower, "2ip.key") {
		return "sensitive-looking output"
	}
	if strings.ContainsAny(output, "{}[]") {
		return "structured output"
	}
	return "text output"
}

// run selects the fixed production execution policy unless an isolated runner was injected.
func (i Installed) run(ctx context.Context, name string, args ...string) error {
	if i.Run != nil {
		return i.Run(ctx, name, args...)
	}
	return RunCommand(ctx, name, args...)
}

// Apply translates one known operation to the unchanged compiler argument sequence.
func (i Installed) Apply(ctx context.Context, r Request) error {
	args := []string{"-I", Compiler}
	switch r.Operation {
	case Validate:
		args = append(args, "--validate-managed", r.Source)
	case Rebind:
		args = append(args, "--rebind", r.Source, r.Stage, r.ID, r.Target)
	case Reorder:
		args = append(args, "--reorder", r.Source, r.Stage)
		if r.UplinkDevice != "" {
			args = append(args, r.UplinkDevice, "--keenetic")
		}
	case CountryMap:
		args = append(args, "--country-map", r.Source, r.Stage)
	case SaveList:
		args = append(args, "--save-list", r.Source, r.Stage, r.ID)
	case DeleteList:
		args = append(args, "--delete-list", r.Source, r.Stage, r.ID)
	case MoveExit:
		args = append(args, "--move-exit", r.Source, r.Stage, r.ID, r.ExpectedGroup, r.Target, strconv.Itoa(r.Priority))
	case CreateGroup:
		args = append(args, "--create-group", r.Source, r.Stage, r.ID, r.Name)
	case RenameGroup:
		args = append(args, "--rename-group", r.Source, r.Stage, r.ID, r.Name)
	case DeleteGroup:
		args = append(args, "--delete-group", r.Source, r.Stage, r.ID)
	case Compile:
		args = append(args, filepath.Join(r.Stage, "profile.json"), r.Stage, r.Stage)
		if r.PreserveWireguard {
			args = append(args, r.Source)
		}
		args = appendPlatformCompileFlag(args)
	case KeeneticIngress:
		action := "disable"
		if r.Enabled {
			action = "enable"
		}
		args = append(args, "--keenetic-ingress", r.Source, r.Stage, action)
		args = appendPlatformCompileFlag(args)
	default:
		return errors.New("unknown profile operation")
	}
	return i.run(ctx, Python, args...)
}

// CheckBackend asks the installed sing-box to validate the staged configuration without starting it.
func (i Installed) CheckBackend(ctx context.Context, path string) error {
	return runBackendCheck(ctx, path, func(ctx context.Context, timeout time.Duration, name string, args ...string) error {
		if i.Run != nil {
			return i.Run(ctx, name, args...)
		}
		return runCommand(ctx, name, timeout, args...)
	})
}

// runBackendCheck applies the dedicated bound to the fixed sing-box validation command.
func runBackendCheck(ctx context.Context, path string, run func(context.Context, time.Duration, string, ...string) error) error {
	name, args := backendCheckCommand(path)
	return run(ctx, backendCheckTimeout, name, args...)
}
