//go:build keenetic

package binding

import (
	"testing"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// TestKeeneticIngressSnapshotAllowsOnlyManagedDefaultOutput checks the ingress migration accepts its exact WAN addition and rejects unrelated snapshot edits.
func TestKeeneticIngressSnapshotAllowsOnlyManagedDefaultOutput(t *testing.T) {
	current := controller.Config{
		Groups:  []routing.Group{{ID: "rest-of-world", Name: "Остальной мир", Exits: []string{"zarubin", "laurel"}}},
		Lists:   []routing.List{{ID: "sites", Group: "rest-of-world", Masks: []string{"*.example"}}},
		Healthy: map[string]bool{"zarubin": true, "laurel": true},
	}
	unchanged := current
	if !keeneticIngressSnapshotAllowed(current, unchanged, true) || !keeneticIngressSnapshotAllowed(current, unchanged, false) {
		t.Fatal("unchanged snapshot was rejected")
	}

	withUplink := current
	withUplink.Groups = append([]routing.Group(nil), current.Groups...)
	withUplink.Groups[0].Exits = append(append([]string(nil), current.Groups[0].Exits...), keeneticUplinkUnderlayID)
	if !keeneticIngressSnapshotAllowed(current, withUplink, true) {
		t.Fatal("managed default-group WAN output was rejected")
	}
	if keeneticIngressSnapshotAllowed(current, withUplink, false) {
		t.Fatal("disabled ingress accepted a changed snapshot")
	}

	changedHealth := withUplink
	changedHealth.Healthy = map[string]bool{"zarubin": false, "laurel": true}
	if keeneticIngressSnapshotAllowed(current, changedHealth, true) {
		t.Fatal("unrelated availability change was accepted")
	}
	changedList := current
	changedList.Lists = append([]routing.List(nil), current.Lists...)
	changedList.Lists[0].Group = "another-group"
	if keeneticIngressSnapshotAllowed(current, changedList, true) {
		t.Fatal("unrelated list change was accepted")
	}
}
