package binding

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// ErrInvalidOrder rejects incomplete orders, duplicate IDs, unknown members and unsupported exit additions.
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
			if id == "" || seen[id] || PlatformChannelRole(id) == panelmodel.ChannelRoleInput {
				return nil, ErrInvalidOrder
			}
			seen[id] = true
			exits[id] = true
		}
		topology[group.ID] = exits
	}
	return topology, nil
}

// ValidateOrder preserves every group and existing exit, allowing only one new platform-reserved exit.
func ValidateOrder(change panelmodel.GroupOrderChange) error {
	expected, err := members(change.Expected)
	if err != nil {
		return err
	}
	desired, err := members(change.Groups)
	if err != nil || len(desired) != len(expected) {
		return ErrInvalidOrder
	}
	allExits := make(map[string]bool)
	for _, exits := range expected {
		for id := range exits {
			allExits[id] = true
		}
	}
	addedPlatformExit := false
	for group, exits := range desired {
		if _, ok := expected[group]; !ok {
			return ErrInvalidOrder
		}
		for id := range exits {
			if !allExits[id] {
				if PlatformOutputID() == "" || id != PlatformOutputID() || addedPlatformExit {
					return ErrInvalidOrder
				}
				addedPlatformExit = true
				continue
			}
			delete(allExits, id)
		}
	}
	if len(allExits) != 0 {
		return ErrInvalidOrder
	}
	return nil
}

// ApplyOrder applies a validated reorder without adding a platform exit and confirms it through the managed transaction.
func (e Engine) ApplyOrder(ctx context.Context, change panelmodel.GroupOrderChange) error {
	return e.ApplyOrderWithUplink(ctx, change, "")
}

// ApplyOrderWithUplink permits one platform output to be added while preserving the group's selected default.
func (e Engine) ApplyOrderWithUplink(ctx context.Context, change panelmodel.GroupOrderChange, uplinkDevice string) error {
	if err := ValidateOrder(change); err != nil {
		return err
	}
	addsPlatformExit := orderAddsPlatformExit(change)
	if addsPlatformExit && platformOutputNeedsDeviceBinding() != (uplinkDevice != "") {
		return ErrInvalidOrder
	}
	if !addsPlatformExit && uplinkDevice != "" {
		return ErrInvalidOrder
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
		if err := e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.Reorder, Source: e.dir, Stage: dir, UplinkDevice: uplinkDevice}); err != nil {
			return err
		}
		return os.Remove(request)
	}
	return e.applyWithNoChangeCheck(ctx, stageOrder, check, sameOrder(change.Expected, change.Groups), func(stage string) (bool, error) {
		return sameBackendRoute(e.dir, stage)
	})
}

// sameBackendRoute confirms an unchanged order is a true no-op only when current and staged routes match.
func sameBackendRoute(currentDir, stagedDir string) (bool, error) {
	readRoute := func(directory string) (any, error) {
		data, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
		if err != nil {
			return nil, ErrUnavailable
		}
		var backend struct {
			Route any `json:"route"`
		}
		if err := json.Unmarshal(data, &backend); err != nil || backend.Route == nil {
			return nil, ErrUnavailable
		}
		return backend.Route, nil
	}
	current, err := readRoute(currentDir)
	if err != nil {
		return false, err
	}
	staged, err := readRoute(stagedDir)
	if err != nil {
		return false, err
	}
	return reflect.DeepEqual(current, staged), nil
}

// orderAddsPlatformExit reports whether the desired topology introduces the platform's reserved direct output.
func orderAddsPlatformExit(change panelmodel.GroupOrderChange) bool {
	id := PlatformOutputID()
	if id == "" {
		return false
	}
	for _, group := range change.Expected {
		if slices.Contains(group.Exits, id) {
			return false
		}
	}
	for _, group := range change.Groups {
		if slices.Contains(group.Exits, id) {
			return true
		}
	}
	return false
}
