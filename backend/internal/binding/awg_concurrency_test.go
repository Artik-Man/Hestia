package binding

import (
	"context"
	"errors"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestOverlappingAWGImports retries a competing writer after the first runtime probe and verifies both persisted assignments.
func TestOverlappingAWGImports(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	a := panelmodel.AWGSaveRequest{ID: "first", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	b := panelmodel.AWGSaveRequest{ID: "second", Group: "ru", Priority: 1, Profile: connectorTestConfig}
	checked := false
	e.readyWait = func(ctx context.Context, id string) error {
		if id == a.ID {
			checked = true
			if err := e.ApplyAWG(ctx, b, false); !errors.Is(err, ErrConflict) {
				t.Fatalf("competing writer while first activation is uncommitted: %v", err)
			}
		}
		return nil
	}
	if err := e.ApplyAWG(ctx, a, false); err != nil || !checked {
		t.Fatalf("first activation: checked=%v err=%v", checked, err)
	}
	if err := e.ApplyAWG(ctx, b, false); err != nil {
		t.Fatalf("retry after commit: %v", err)
	}
	profile, err := readStoredProfile(e.dir)
	if err != nil || len(profile.Connectors) != 2 {
		t.Fatalf("lost connector: %v", err)
	}
	if profile.Connectors[0].Slot != 0 || profile.Connectors[1].Slot != 1 {
		t.Fatalf("unexpected persisted slots: %d, %d", profile.Connectors[0].Slot, profile.Connectors[1].Slot)
	}
}
