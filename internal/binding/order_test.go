package binding

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestOrderPermutation checks that full group and member permutations cannot add, drop or transfer exits.
func TestOrderPermutation(t *testing.T) {
	original := []panelmodel.OrderedGroup{{ID: "fi", Exits: []string{"a", "b"}}, {ID: "ru", Exits: []string{"c"}}}
	reversed := []panelmodel.OrderedGroup{{ID: "ru", Exits: []string{"c"}}, {ID: "fi", Exits: []string{"b", "a"}}}
	if err := ValidateOrder(panelmodel.GroupOrderChange{Expected: original, Groups: reversed}); err != nil {
		t.Fatal(err)
	}
	cases := [][]panelmodel.OrderedGroup{
		reversed[:1], {original[0], original[0]}, {{ID: "fi", Exits: []string{"b", "b"}}, original[1]},
		{{ID: "fi", Exits: []string{"c"}}, {ID: "ru", Exits: []string{"a", "b"}}},
		{{ID: "fi", Exits: nil}, original[1]}, {{ID: "unknown", Exits: []string{"a", "b"}}, original[1]},
	}
	for _, groups := range cases {
		if err := ValidateOrder(panelmodel.GroupOrderChange{Expected: original, Groups: groups}); !errors.Is(err, ErrInvalidOrder) {
			t.Errorf("accepted %v", groups)
		}
	}
}

// TestOrderCAS checks a stale baseline against only installed topology and before invoking external commands.
func TestOrderCAS(t *testing.T) {
	e := testEngine(t)
	e.run = func(context.Context, string, ...string) error { t.Fatal("stale change reached compiler"); return nil }
	fi := panelmodel.OrderedGroup{ID: "fi", Exits: []string{}}
	ru := panelmodel.OrderedGroup{ID: "ru", Exits: []string{}}
	err := e.ApplyOrder(context.Background(), panelmodel.GroupOrderChange{Expected: []panelmodel.OrderedGroup{ru, fi}, Groups: []panelmodel.OrderedGroup{fi, ru}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale order: %v", err)
	}
}

// TestApplyOrderReadsLatestTopology checks that concurrent health or list edits do not invalidate an unchanged order.
// The simulated compiler takes its input from the private request file used by the production transaction.
func TestApplyOrderReadsLatestTopology(t *testing.T) {
	e := testEngine(t)
	fi := panelmodel.OrderedGroup{ID: "fi", Exits: []string{"fi2", "fi1"}}
	ru := panelmodel.OrderedGroup{ID: "ru", Exits: []string{}}
	old := []panelmodel.OrderedGroup{fi, ru}
	change := panelmodel.GroupOrderChange{Expected: old, Groups: []panelmodel.OrderedGroup{ru, {ID: "fi", Exits: []string{"fi1", "fi2"}}}}
	live := map[string]any{"groups": old, "healthy": map[string]bool{"fi2": true}, "lists": []map[string]any{{"id": "new-list", "group": "ru", "masks": []string{"*.org"}}}}
	encode := func(dest string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	encode(filepath.Join(e.dir, "snapshot.json"), live)
	confirmed := false
	e.run = func(_ context.Context, name string, args ...string) error {
		if name == python && args[1] == profile {
			if args[2] != "--reorder" || len(args) != 5 {
				t.Fatalf("order in argv: %v", args)
			}
			dir := args[4]
			req := filepath.Join(dir, "desired-order.json")
			info, err := os.Lstat(req)
			if err != nil || info.Mode() != 0600 {
				t.Fatal("request file not private", err)
			}
			raw, err := os.ReadFile(req)
			if err != nil {
				t.Fatal(err)
			}
			var desired []panelmodel.OrderedGroup
			if err := json.Unmarshal(raw, &desired); err != nil || !sameOrder(desired, change.Groups) {
				t.Fatal("wrong request", err)
			}
			for _, file := range managedFiles {
				value := "new"
				if file == "profile.json" {
					value = `{"connectors":[]}`
				}
				if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			live["groups"] = desired
			encode(filepath.Join(dir, "snapshot.json"), live)
			writeTestDigests(t, dir)
		} else if name == python && args[1] == smoke && len(args) == 2 {
			confirmed = true
			if _, err := os.Stat(filepath.Join(e.dir, pending, "desired-order.json")); !os.IsNotExist(err) {
				t.Fatal("request leaked into journal")
			}
		}
		return nil
	}
	if err := e.ApplyOrder(context.Background(), change); err != nil || !confirmed {
		t.Fatalf("change not confirmed: %v", err)
	}
	if err := e.ApplyOrder(context.Background(), change); !errors.Is(err, ErrConflict) {
		t.Fatalf("replayed stale order: %v", err)
	}
}
