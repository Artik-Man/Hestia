package binding

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestAdministrativeConnectionState persists VPN state and retains group placement, secret bytes and source readiness.
func TestAdministrativeConnectionState(t *testing.T) {
	e := connectorTestEngine(t)
	id := "12345678-1234-4abc-8123-456789abcdef"
	request := panelmodel.AWGSaveRequest{Name: "VPN", ID: id, Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), request, false); err != nil {
		t.Fatal(err)
	}
	secret := mustReadTestFile(t, filepath.Join(e.dir, awgTreeName, id, "profile.conf"))
	for _, enabled := range []bool{false, false, true} {
		if err := e.SetConnectionEnabled(context.Background(), id, enabled); err != nil {
			t.Fatal(err)
		}
		current, err := readStoredProfile(e.dir)
		if err != nil || current.connectionEnabled(id) != enabled || current.Connectors[0].Status != "ready" || !current.Healthy[id] || current.Groups[0].Exits[0] != id {
			t.Fatalf("lost source state: %#v %v", current, err)
		}
		got, err := e.ConnectionEnabled(id)
		if err != nil || got != enabled {
			t.Fatalf("projection=%v %v", got, err)
		}
		if string(mustReadTestFile(t, filepath.Join(e.dir, awgTreeName, id, "profile.conf"))) != string(secret) {
			t.Fatal("secret changed")
		}
		ready, err := readyAWG(e.dir)
		_, running := ready[id]
		if err != nil || running != enabled {
			t.Fatalf("runtime plan=%v %v", ready, err)
		}
		var snapshot struct {
			Healthy map[string]bool `json:"healthy"`
		}
		if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(e.dir, "snapshot.json")), &snapshot); err != nil {
			t.Fatal(err)
		}
		if snapshot.Healthy[id] != enabled {
			t.Fatal("snapshot bypassed administrative state")
		}
	}
	if err := e.SetConnectionEnabled(context.Background(), "missing", false); err == nil {
		t.Fatal("unknown virtual connection accepted")
	}
	if err := e.SetConnectionEnabled(context.Background(), id, false); err != nil {
		t.Fatal(err)
	}
	// Saving metadata while disabled must not restart or silently re-enable its runtime.
	e.readyWait = func(context.Context, string) error { t.Fatal("disabled profile restarted during edit"); return nil }
	request.Name = "Renamed disabled VPN"
	if err := e.ApplyAWG(context.Background(), request, true); err != nil {
		t.Fatal(err)
	}
	if enabled, err := e.ConnectionEnabled(id); err != nil || enabled {
		t.Fatal("edit re-enabled connection")
	}
	if err := e.DeleteAWG(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	current, err := readStoredProfile(e.dir)
	if err != nil || slices.Contains(current.DisabledConnections, id) {
		t.Fatalf("deleted ID retained: %v", err)
	}
}

// TestAdministrativeIngressIsNotVirtual excludes platform channels independently of their interface transport type.
func TestAdministrativeIngressIsNotVirtual(t *testing.T) {
	p := storedProfile{Interfaces: []storedInterface{{ID: "wg-keenetic", Type: "wireguard"}, {ID: "wan", Type: "direct"}, {ID: "native", Type: "wireguard"}}}
	if p.virtualConnection("wg-keenetic") || p.virtualConnection("wan") || !p.virtualConnection("native") {
		t.Fatal("virtual connection boundary changed")
	}
	e := connectorTestEngine(t)
	original := mustReadTestFile(t, filepath.Join(e.dir, "profile.json"))
	if err := e.SetConnectionEnabled(context.Background(), "missing", false); err == nil {
		t.Fatal("missing connection accepted")
	}
	actual, err := os.ReadFile(filepath.Join(e.dir, "profile.json"))
	if err != nil || string(actual) != string(original) {
		t.Fatal("failed toggle changed profile")
	}
}
