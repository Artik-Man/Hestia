package binding

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

type fakePhysicalManager struct {
	inventory      panelmodel.PhysicalInventory
	saved, deleted string
}

// Inventory supplies a deterministic, secret-free adapter and profile inventory.
func (f *fakePhysicalManager) Inventory(context.Context) (panelmodel.PhysicalInventory, error) {
	return f.inventory, nil
}

// SaveWiFi records the profile ID selected under the routing lock without keeping supplied credentials.
func (f *fakePhysicalManager) SaveWiFi(_ context.Context, id string, _ panelmodel.WifiConnectionSettings) error {
	f.saved = id
	return nil
}

// DeleteWiFi records the owned profile selected for deletion.
func (f *fakePhysicalManager) DeleteWiFi(_ context.Context, id string) error {
	f.deleted = id
	return nil
}

// TestPhysicalConnections associates shared direct bindings, includes unplugged adapters, and excludes virtual exits.
func TestPhysicalConnections(t *testing.T) {
	e := connectorTestEngine(t)
	source := `{"version":2,"interfaces":[{"id":"wired","type":"direct","bind_interface":"eth0"},{"id":"second","type":"direct","bind_interface":"eth0"},{"id":"missing","type":"direct","bind_interface":"eth7"},{"id":"wg","type":"wireguard"}]}`
	if err := os.WriteFile(filepath.Join(e.dir, "profile.json"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	m := &fakePhysicalManager{inventory: panelmodel.PhysicalInventory{Interfaces: []panelmodel.PhysicalInterface{{InterfaceName: "eth0", Kind: "ethernet", Present: true, Online: false}, {InterfaceName: "wlan0", Kind: "wifi", Present: true}}}}
	got, err := e.PhysicalConnections(context.Background(), m)
	if err != nil || len(got.Interfaces) != 3 {
		t.Fatalf("inventory: %+v, %v", got, err)
	}
	a, b, c := got.Interfaces[0], got.Interfaces[1], got.Interfaces[2]
	if !a.Present || a.Online || !slices.Equal(a.ExitIDs, []string{"wired", "second"}) || b.ExitIDs == nil || len(b.ExitIDs) > 0 || c.InterfaceName != "eth7" || c.Present || c.Online || !slices.Equal(c.ExitIDs, []string{"missing"}) || got.WifiProfiles == nil {
		t.Fatalf("invalid mapping: %+v", got)
	}
}

// TestChangeWifi confirms create IDs, existence checks, serialization and unsupported-backend rejection before mutation.
func TestChangeWifi(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	m := &fakePhysicalManager{}
	settings := panelmodel.WifiConnectionSettings{InterfaceName: "wlan0", SSID: "Lab", Band: "5", Security: "open"}
	if err := e.ChangeWifi(ctx, m, "", &settings); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	m.inventory.WifiAvailable = true
	if err := e.ChangeWifi(ctx, m, "", &settings); err != nil || !wifiID.MatchString(m.saved) {
		t.Fatalf("create id=%s err=%v", m.saved, err)
	}
	id := m.saved
	if err := e.ChangeWifi(ctx, m, id, &settings); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	m.inventory.WifiProfiles = []panelmodel.WifiConnection{{ID: id}}
	if err := e.ChangeWifi(ctx, m, id, &settings); err != nil {
		t.Fatal(err)
	}
	lock, err := e.acquire(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ChangeWifi(ctx, m, id, nil); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	lock.Close()
	if err := e.ChangeWifi(ctx, m, id, nil); err != nil || m.deleted != id {
		t.Fatalf("delete: %v", err)
	}
}
