package profileexec

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunCommandReportsExitCodeAndRedactsOutput verifies command failures retain useful safe diagnostics.
func TestRunCommandReportsExitCodeAndRedactsOutput(t *testing.T) {
	err := runCommand(context.Background(), "/bin/sh", time.Second, "-c", `printf 'token=abc123 path=/private/profile\n' >&2; printf 'password=hidden\n'; exit 7`)
	if err == nil {
		t.Fatal("expected command failure")
	}
	message := err.Error()
	for _, want := range []string{"profile-helper exited with code 7", "stderr sensitive-looking output withheld", "stdout withheld"} {
		if !strings.Contains(message, want) {
			t.Errorf("diagnostic %q does not contain %q", message, want)
		}
	}
	for _, secret := range []string{"abc123", "hidden", "/private/profile", "token=", "password="} {
		if strings.Contains(message, secret) {
			t.Errorf("diagnostic exposed %q: %s", secret, message)
		}
	}
}

// TestRunCommandWithholdsAuthorizationValues verifies raw credential output never appears in process errors.
func TestRunCommandWithholdsAuthorizationValues(t *testing.T) {
	err := runCommand(context.Background(), "/bin/sh", time.Second, "-c", `printf 'Authorization: Bearer highly-sensitive-token\n' >&2; exit 1`)
	if err == nil {
		t.Fatal("expected command failure")
	}
	message := err.Error()
	if strings.Contains(message, "highly-sensitive-token") || strings.Contains(message, "Bearer") {
		t.Fatalf("authorization value leaked: %q", message)
	}
	if !strings.Contains(message, "stderr sensitive-looking output withheld") {
		t.Fatalf("sensitive output category missing: %q", message)
	}
}

// TestRunCommandDistinguishesDeadlineFromSignal verifies a timed-out child is classified separately from an external signal.
func TestRunCommandDistinguishesDeadlineFromSignal(t *testing.T) {
	err := runCommand(context.Background(), "/bin/sh", 20*time.Millisecond, "-c", "sleep 1")
	var failure commandFailure
	if !errors.As(err, &failure) || !failure.timedOut || failure.signal == "" {
		t.Fatalf("timeout diagnostics = %#v (%v)", failure, err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}

	err = runCommand(context.Background(), "/bin/sh", time.Second, "-c", "kill -KILL $$")
	if !errors.As(err, &failure) || failure.timedOut || failure.signal != syscall.SIGKILL.String() {
		t.Fatalf("signal diagnostics = %#v (%v)", failure, err)
	}
	if !strings.Contains(err.Error(), "terminated by signal killed") {
		t.Fatalf("signal error = %v", err)
	}
}

// TestRunCommandReportsLaunchFailureWithoutPath verifies executable paths are not copied into diagnostics.
func TestRunCommandReportsLaunchFailureWithoutPath(t *testing.T) {
	err := runCommand(context.Background(), "/private/missing/hestia-helper", time.Second)
	var failure commandFailure
	if !errors.As(err, &failure) || !failure.launchErr {
		t.Fatalf("launch diagnostics = %#v (%v)", failure, err)
	}
	if strings.Contains(err.Error(), "/private/missing") {
		t.Fatalf("launch error exposed path: %v", err)
	}
}

// TestBoundedBufferMarksTruncation confirms child output is capped without interrupting the writer.
func TestBoundedBufferMarksTruncation(t *testing.T) {
	buffer := &boundedBuffer{}
	written, err := buffer.Write([]byte(strings.Repeat("x", maxDiagnosticOutput+10)))
	if err != nil || written != maxDiagnosticOutput+10 {
		t.Fatalf("Write() = %d, %v", written, err)
	}
	if buffer.Len() != maxDiagnosticOutput || !buffer.truncated {
		t.Fatalf("buffer length/truncation = %d/%t", buffer.Len(), buffer.truncated)
	}
}

// TestCommandRoleUsesFixedLabels prevents arbitrary executable paths from entering process diagnostics.
func TestCommandRoleUsesFixedLabels(t *testing.T) {
	if got := commandRole("/arbitrary/path/python3"); got != "profile-compiler" {
		t.Fatalf("python role = %q", got)
	}
	if got := commandRole("/arbitrary/path/ld-linux-aarch64.so.1"); got != "backend-validator" {
		t.Fatalf("loader role = %q", got)
	}
	if got := commandRole("/private/secret/path"); got != "profile-helper" {
		t.Fatalf("unknown role = %q", got)
	}
}

// TestBackendCheckUsesLongBound verifies sing-box validation exceeds the observed cutoff while keeping a finite deadline.
func TestBackendCheckUsesLongBound(t *testing.T) {
	var gotTimeout time.Duration
	called := false
	run := func(_ context.Context, timeout time.Duration, name string, args ...string) error {
		called = true
		gotTimeout = timeout
		if name == "" || len(args) == 0 {
			t.Fatal("backend validator command was empty")
		}
		return nil
	}
	if err := runBackendCheck(context.Background(), "/staged/sing-box.json", run); err != nil {
		t.Fatalf("runBackendCheck() error = %v", err)
	}
	if !called {
		t.Fatal("backend validator runner was not called")
	}
	if gotTimeout <= commandTimeout {
		t.Fatalf("backend timeout = %s, must exceed the prior %s cutoff", gotTimeout, commandTimeout)
	}
	if gotTimeout != 10*time.Minute || gotTimeout <= 0 {
		t.Fatalf("backend timeout = %s, want bounded 10m", gotTimeout)
	}
}
