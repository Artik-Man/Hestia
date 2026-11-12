//go:build linux && keenetic

package awg

import (
	"strconv"
	"testing"
)

// TestSlotFromManifestResolvesLegacyRulePriorities verifies the slot lookup accepts the exact pre-migration mark, table, device, and priority tuple.
func TestSlotFromManifestResolvesLegacyRulePriorities(t *testing.T) {
	for _, test := range []struct {
		name        string
		manifest    routeManifest
		oldPriority int
	}{
		{
			name:        "mark route",
			manifest:    routeManifest{ID: "connector", Mark: "0x202", Table: "202", Priority: "1002", Device: "awg0"},
			oldPriority: 1002,
		},
		{
			name:        "outer guard",
			manifest:    routeManifest{ID: "connector", Mark: "0x51000", Table: "", Priority: "1100", Device: "lo"},
			oldPriority: 1100,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			slot, ok := slotFromManifest(test.manifest, test.oldPriority)
			if !ok || slot != 0 {
				t.Fatalf("slotFromManifest(%+v, %s) = (%d, %v), want (0, true)", test.manifest, strconv.Itoa(test.oldPriority), slot, ok)
			}
		})
	}
}
