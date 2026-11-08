package profileexec

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// TestApplyPreservesArguments checks the externally established compiler CLI for every supported transformation.
func TestApplyPreservesArguments(t *testing.T) {
	cases := []struct {
		op   Operation
		args []string
	}{
		{Validate, []string{"--validate-managed", "source"}},
		{Rebind, []string{"--rebind", "source", "stage", "id", "target"}},
		{Reorder, []string{"--reorder", "source", "stage"}},
		{CountryMap, []string{"--country-map", "source", "stage"}},
		{SaveList, []string{"--save-list", "source", "stage", "id"}},
		{DeleteList, []string{"--delete-list", "source", "stage", "id"}},
		{MoveExit, []string{"--move-exit", "source", "stage", "id", "old", "target", "4"}},
		{CreateGroup, []string{"--create-group", "source", "stage", "id", "name"}},
		{RenameGroup, []string{"--rename-group", "source", "stage", "id", "name"}},
		{DeleteGroup, []string{"--delete-group", "source", "stage", "id"}},
		{Compile, []string{"stage/profile.json", "stage", "stage", "source"}},
	}
	for _, c := range cases {
		r := Request{Operation: c.op, Source: "source", Stage: "stage", ID: "id", Target: "target", Name: "name", ExpectedGroup: "old", Priority: 4, PreserveWireguard: true}
		called := false
		adapter := Installed{Run: func(_ context.Context, name string, args ...string) error {
			called = true
			expected := append([]string{"-I", Compiler}, c.args...)
			if c.op == Compile {
				expected = appendPlatformCompileFlag(expected)
			}
			if name != Python || !reflect.DeepEqual(args, expected) {
				t.Fatalf("operation %d got %s %v", c.op, name, args)
			}
			return nil
		}}
		if err := adapter.Apply(context.Background(), r); err != nil || !called {
			t.Fatalf("operation %d: %v", c.op, err)
		}
	}
}

// TestInvalidOperationCannotExecute verifies unknown platform operations never invoke a command.
func TestInvalidOperationCannotExecute(t *testing.T) {
	adapter := Installed{Run: func(context.Context, string, ...string) error { t.Fatal("unexpected execution"); return nil }}
	if adapter.Apply(context.Background(), Request{}) == nil {
		t.Fatal("unknown operation accepted")
	}
}

// TestCompilerFailurePropagates preserves partial-operation failure for the transaction coordinator.
func TestCompilerFailurePropagates(t *testing.T) {
	failure := errors.New("failed")
	adapter := Installed{Run: func(context.Context, string, ...string) error { return failure }}
	if !errors.Is(adapter.Apply(context.Background(), Request{Operation: Validate}), failure) {
		t.Fatal("compiler failure lost")
	}
	if !errors.Is(adapter.CheckBackend(context.Background(), "stage/sing-box.json"), failure) {
		t.Fatal("validator failure lost")
	}
}
