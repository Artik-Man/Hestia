package awg

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type fakeRuntime struct {
	err   error
	calls int
}

// Check records one bounded fake runtime invocation and returns its configured outcome.
func (f *fakeRuntime) Check(_ context.Context, _ Profile) error {
	f.calls++
	return f.err
}

// TestManagerCheckUsesFakeRuntimeWithoutPersisting confirms candidate checks do not mutate store state.
func TestManagerCheckUsesFakeRuntimeWithoutPersisting(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	runtime := &fakeRuntime{}
	manager := NewManager(store, runtime)
	if err := manager.Check(context.Background(), []byte(validProfile)); err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("runtime check count = %d, want 1", runtime.calls)
	}
	connections, err := manager.List()
	if err != nil || len(connections) != 0 {
		t.Fatalf("candidate check persisted a connection: %#v, %v", connections, err)
	}
}

// TestManagerCheckReportsRuntimeFailureWithoutLeakingSecrets verifies failed probes do not return profile data.
func TestManagerCheckReportsRuntimeFailureWithoutLeakingSecrets(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	runtime := &fakeRuntime{err: errors.New("probe failed")}
	manager := NewManager(store, runtime)
	if err := manager.Check(context.Background(), []byte(validProfile)); err == nil || err.Error() != "probe failed" {
		t.Fatalf("unexpected Check error: %v", err)
	}
	if runtime.calls != 1 {
		t.Fatalf("runtime check count = %d, want 1", runtime.calls)
	}
}

// TestManagerCheckWithoutRuntimeFailsClosed ensures a missing production probe cannot report success.
func TestManagerCheckWithoutRuntimeFailsClosed(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	manager := NewManager(store, nil)
	if err := manager.Check(context.Background(), []byte(validProfile)); !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Check error = %v, want ErrRuntimeUnavailable", err)
	}
}
