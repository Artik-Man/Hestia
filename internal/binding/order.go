package binding

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// ErrInvalidOrder rejects incomplete orders, duplicate IDs and moves of exits between groups.
var ErrInvalidOrder = errors.New("requested order must permute every existing group and its exits")

// sameOrder compares only the group and per-group exit sequences.
func sameOrder(a, b []panelmodel.OrderedGroup) bool {
	return slices.EqualFunc(a, b, func(x, y panelmodel.OrderedGroup) bool { return x.ID == y.ID && slices.Equal(x.Exits, y.Exits) })
}

// members indexes a complete order with unique group and exit IDs. Empty groups have explicit empty arrays.
func members(groups []panelmodel.OrderedGroup) (map[string]map[string]bool, error) {
	if len(groups) == 0 {
		return nil, ErrInvalidOrder
	}
	topology := make(map[string]map[string]bool, len(groups))
	seen := map[string]bool{}
	for _, group := range groups {
		if group.ID == "" || seen[group.ID] || group.Exits == nil {
			return nil, ErrInvalidOrder
		}
		seen[group.ID] = true
		exits := make(map[string]bool, len(group.Exits))
		for _, id := range group.Exits {
			if id == "" || seen[id] {
				return nil, ErrInvalidOrder
			}
			seen[id] = true
			exits[id] = true
		}
		topology[group.ID] = exits
	}
	return topology, nil
}

// ValidateOrder requires exactly the same groups and exit memberships on both sides of an edit.
func ValidateOrder(change panelmodel.GroupOrderChange) error {
	expected, err := members(change.Expected)
	if err != nil {
		return err
	}
	desired, err := members(change.Groups)
	if err != nil || len(desired) != len(expected) {
		return ErrInvalidOrder
	}
	for group, exits := range desired {
		before, ok := expected[group]
		if !ok || len(exits) != len(before) {
			return ErrInvalidOrder
		}
		for id := range exits {
			if !before[id] {
				return ErrInvalidOrder
			}
		}
	}
	return nil
}

// ApplyOrder accepts only a permutation of the installed topology and confirms it via the same transaction as list bindings.
func (e Engine) ApplyOrder(ctx context.Context, change panelmodel.GroupOrderChange) error {
	if err := ValidateOrder(change); err != nil {
		return err
	}
	data, err := json.Marshal(change.Groups)
	if err != nil {
		return err
	}
	check := func(snapshot []byte, staged bool) error {
		cfg, err := controller.CheckSnapshot(snapshot)
		if err != nil {
			return ErrUnavailable
		}
		current := make([]panelmodel.OrderedGroup, len(cfg.Groups))
		for i, g := range cfg.Groups {
			current[i] = panelmodel.OrderedGroup{ID: g.ID, Exits: g.Exits}
		}
		if staged {
			if !sameOrder(current, change.Groups) {
				return ErrUnavailable
			}
		} else if !sameOrder(current, change.Expected) {
			return ErrConflict
		}
		return nil
	}
	stageOrder := func(dir string) error {
		// Keep large orders out of argv and out of the persistent rollback journal.
		request := filepath.Join(dir, "desired-order.json")
		if err := os.WriteFile(request, data, 0600); err != nil {
			return err
		}
		if err := e.run(ctx, python, "-I", profile, "--reorder", e.dir, dir); err != nil {
			return err
		}
		return os.Remove(request)
	}
	return e.apply(ctx, stageOrder, check, sameOrder(change.Expected, change.Groups))
}
