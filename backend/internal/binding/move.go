package binding

import (
	"context"
	"reflect"
	"slices"
	"strconv"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/controller"
)

// MoveExit places an installed exit at the requested one-based priority if its current owner matches expectedGroup.
// It preserves all other memberships and profile secrets through the same verified transaction used for group order changes.
func (e Engine) MoveExit(ctx context.Context, id, expectedGroup, targetGroup string, priority int) error {
	if !awg.ValidConnectionID(id) || ValidateGroupID(expectedGroup) != nil || ValidateGroupID(targetGroup) != nil || priority < 1 {
		return ErrInvalidOrder
	}
	var expected controller.Config
	check := func(data []byte, staged bool) error {
		current, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if staged {
			if !reflect.DeepEqual(current, expected) {
				return ErrUnavailable
			}
			return nil
		}
		source, target, position := -1, -1, -1
		for i, group := range current.Groups {
			if group.ID == targetGroup {
				target = i
			}
			if j := slices.Index(group.Exits, id); j >= 0 {
				source, position = i, j
			}
		}
		if source < 0 || target < 0 {
			return ErrNotFound
		}
		if current.Groups[source].ID != expectedGroup {
			return ErrConflict
		}
		expected = current
		group := &expected.Groups[source]
		group.Exits = slices.Delete(group.Exits, position, position+1)
		targetExits := expected.Groups[target].Exits
		if priority > len(targetExits)+1 {
			return ErrInvalidOrder
		}
		expected.Groups[target].Exits = slices.Insert(targetExits, priority-1, id)
		return nil
	}
	prepare := func(stage string) error {
		return e.run(ctx, python, "-I", profile, "--move-exit", e.dir, stage, id, expectedGroup, targetGroup, strconv.Itoa(priority))
	}
	return e.apply(ctx, prepare, check, false)
}
