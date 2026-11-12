//go:build keenetic

package awg

import (
	"context"
	"errors"
	"strconv"
)

// migrateLegacyRouteManifest moves only an exact root-owned pre-migration manifest and its matching rules.
func migrateLegacyRouteManifest(ctx context.Context, path string, expected routeManifest, oldPriority int) error {
	if exists, err := loadRouteManifest(path, expected); err == nil && exists {
		return nil
	}
	legacy := expected
	legacy.Priority = strconv.Itoa(oldPriority)
	exists, err := loadRouteManifest(path, legacy)
	if err != nil || !exists {
		return err
	}
	migrator, ok := newRoutePolicyMigrator(expected, oldPriority)
	if !ok {
		return errors.New("AWG route priority migration is unavailable")
	}
	if err := migrator.MigrateOwnedRulePriority(ctx, legacy.Priority); err != nil {
		return err
	}
	return writeRouteManifest(path, expected)
}

// newRoutePolicyMigrator derives the exact new slot policy from a verified connector manifest.
func newRoutePolicyMigrator(expected routeManifest, oldPriority int) (interface {
	MigrateOwnedRulePriority(context.Context, string) error
}, bool) {
	slot, ok := slotFromManifest(expected, oldPriority)
	if !ok {
		return nil, false
	}
	policy, err := newSlotRoutePolicy(routeRunner, slot)
	if err != nil {
		return nil, false
	}
	migrator, ok := policy.RoutePolicy.(interface {
		MigrateOwnedRulePriority(context.Context, string) error
	})
	if !ok {
		return nil, false
	}
	return migrator, true
}

// slotFromManifest resolves a route allocation without trusting a path-derived slot number.
func slotFromManifest(manifest routeManifest, oldPriority int) (int, bool) {
	for slot := 0; slot < 4; slot++ {
		policy, err := newSlotRoutePolicy(routeRunner, slot)
		if err == nil {
			current := policy.manifest(manifest.ID)
			legacy := current
			legacy.Priority = strconv.Itoa(1002 + slot)
			if current == manifest || (oldPriority == 1002+slot && legacy == manifest) {
				return slot, true
			}
		}
		outer, err := outerPolicy(slot)
		if err == nil {
			current := outer.manifest(manifest.ID)
			legacy := current
			legacy.Priority = strconv.Itoa(1100 + slot)
			if current == manifest || (oldPriority == 1100+slot && legacy == manifest) {
				return slot, true
			}
		}
	}
	return 0, false
}
