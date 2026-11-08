//go:build keenetic

package binding

import (
	"errors"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestEnsurePlatformUnderlayAddsOnlyTheVerifiedUplink checks dynamic device binding and stable routing identity.
func TestEnsurePlatformUnderlayAddsOnlyTheVerifiedUplink(t *testing.T) {
	profile := storedProfile{Groups: []connectorGroup{{ID: "default", DefaultExit: "deny"}}}
	if err := ensurePlatformUnderlay(&profile, "wan9"); err != nil || len(profile.Interfaces) != 1 {
		t.Fatalf("underlay not added: %+v, %v", profile.Interfaces, err)
	}
	if profile.Interfaces[0] != (storedInterface{ID: keeneticUplinkUnderlayID, Type: "direct", BindInterface: "wan9"}) {
		t.Fatalf("unexpected underlay: %+v", profile.Interfaces[0])
	}
	if len(profile.Groups[0].Exits) != 1 || profile.Groups[0].Exits[0] != keeneticUplinkUnderlayID {
		t.Fatalf("direct provider is missing from the managed group: %+v", profile.Groups)
	}
	if profile.Groups[0].DefaultExit != "deny" {
		t.Fatalf("platform underlay changed the group's default exit: %+v", profile.Groups[0])
	}
	if err := ensurePlatformUnderlay(&profile, "wan9"); err != nil || len(profile.Interfaces) != 1 {
		t.Fatalf("underlay append was not idempotent: %+v, %v", profile.Interfaces, err)
	}
	profile.Interfaces[0].BindInterface = "eth2"
	if ensurePlatformUnderlay(&profile, "wan9") == nil {
		t.Fatal("conflicting reserved underlay was accepted")
	}
}

// TestPlatformExitCanBeAddedToGroup accepts exactly one reserved direct exit on Keenetic.
func TestPlatformExitCanBeAddedToGroup(t *testing.T) {
	old := []panelmodel.OrderedGroup{{ID: "main", Exits: []string{"vpn"}}}
	change := panelmodel.GroupOrderChange{Expected: old, Groups: []panelmodel.OrderedGroup{{ID: "main", Exits: []string{"vpn", PlatformUnderlayID()}}}}
	if err := ValidateOrder(change); err != nil {
		t.Fatalf("platform exit addition rejected: %v", err)
	}
	duplicate := panelmodel.GroupOrderChange{Expected: old, Groups: []panelmodel.OrderedGroup{{ID: "main", Exits: []string{PlatformUnderlayID(), PlatformUnderlayID()}}}}
	if !errors.Is(ValidateOrder(duplicate), ErrInvalidOrder) {
		t.Fatal("duplicate platform exit accepted")
	}
}
