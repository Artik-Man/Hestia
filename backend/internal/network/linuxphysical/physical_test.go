package linuxphysical

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const sampleID = "aabbccdd-1122-4455-8899-aabbccddeeff"

// TestMainDefaultRouteDeviceSelectsBestMetric verifies that dynamic uplink discovery follows the kernel's preferred route.
func TestMainDefaultRouteDeviceSelectsBestMetric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route")
	contents := "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"wan8 00000000 0100000A 0003 0 0 200 00000000 0 0 0\n" +
		"wan9 00000000 0100000A 0003 0 0 100 00000000 0 0 0\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	device, err := mainDefaultRouteDeviceAt(path)
	if err != nil || device != "wan9" {
		t.Fatalf("expected preferred uplink wan9, got %q: %v", device, err)
	}
	contents = strings.Replace(contents, "wan8 00000000 0100000A 0003 0 0 200", "wan8 00000000 0100000A 0003 0 0 100", 1)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	device, err = mainDefaultRouteDeviceAt(path)
	if err != nil || device != "" {
		t.Fatalf("equal-metric uplinks should remain ambiguous, got %q: %v", device, err)
	}
}

// fixtureManager supplies a disconnected wireless device, a down Ethernet port, and a virtual bridge that must be ignored.
func fixtureManager(t *testing.T) Manager {
	t.Helper()
	m := Manager{ownerUID: uint32(os.Geteuid()), sysfs: t.TempDir(), directory: t.TempDir()}
	for _, name := range []string{"wlan0", "eth0", "br0"} {
		dir := filepath.Join(m.sysfs, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if name != "br0" {
			if err := os.Mkdir(filepath.Join(dir, "device"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if name == "wlan0" {
			if err := os.Mkdir(filepath.Join(dir, "phy80211"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		for attr, v := range map[string]string{"type": "1\n", "carrier": "0\n"} {
			if err := os.WriteFile(filepath.Join(dir, attr), []byte(v), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return m
}

// sampleSettings produces a synthetic WPA station with punctuation, Unicode, and significant whitespace.
func sampleSettings() panelmodel.WifiConnectionSettings {
	return panelmodel.WifiConnectionSettings{InterfaceName: "wlan0", Band: "5", Security: "wpa-psk", SSID: " Café;\\5 ", Password: " pass\\phrase; "}
}

// TestPhysicalInventoryWithoutManager verifies physical unplugged devices stay visible and no fake WLAN capability is advertised.
func TestPhysicalInventoryWithoutManager(t *testing.T) {
	m := fixtureManager(t)
	m.command = func(context.Context, ...string) (string, error) { return "", errService }
	result, err := m.Inventory(context.Background())
	if err != nil || result.WifiAvailable || len(result.Interfaces) != 2 || result.Interfaces[0].Kind != "ethernet" || result.Interfaces[0].Online || !result.Interfaces[0].Present || result.Interfaces[1].Kind != "wifi" {
		t.Fatalf("unexpected inventory %#v, %v", result, err)
	}
}

// TestWiFiProfileLifecycle verifies constrained activation, owned-file rollback, secret retention, deletion and the public-only inventory.
func TestWiFiProfileLifecycle(t *testing.T) {
	m := fixtureManager(t)
	s := sampleSettings()
	path := filepath.Join(m.directory, wifiFilename(sampleID))
	active, loaded, failNext := false, false, false
	m.command = func(_ context.Context, args ...string) (string, error) {
		cmd := strings.Join(args, " ")
		if strings.Contains(cmd, s.Password) {
			t.Fatal("credential in process arguments")
		}
		switch {
		case strings.HasSuffix(cmd, "show --active"):
			if active {
				return sampleID + ":wlan0", nil
			}
		case strings.Contains(cmd, "UUID,FILENAME"):
			if loaded {
				return sampleID + ":" + path, nil
			}
		case strings.Contains(cmd, "GENERAL.STATE"):
			if active {
				return "100 (connected)", nil
			}
			return "30 (disconnected)", nil
		case cmd == "connection load "+path:
			loaded = true
		case cmd == "--wait 25 connection up uuid "+sampleID+" ifname wlan0":
			if failNext {
				failNext = false
				return "", errService
			}
			active = true
		case cmd == "--wait 10 connection delete uuid "+sampleID:
			loaded, active = false, false
		default:
			t.Errorf("unexpected command %s", cmd)
		}
		return "", nil
	}
	ctx := context.Background()
	if err := m.SaveWiFi(ctx, sampleID, s); err != nil {
		t.Fatal(err)
	}
	profile, original, err := m.readProfile(sampleID)
	if err != nil || profile.SSID != s.SSID || profile.Band != "5" || !bytes.Contains(original, []byte("oif wlan0 table")) || !bytes.Contains(original, []byte("ignore-auto-dns=true")) {
		t.Fatal("invalid private profile", err)
	}
	inv, err := m.Inventory(ctx)
	if err != nil || len(inv.WifiProfiles) != 1 || !inv.WifiProfiles[0].Active {
		t.Fatal("missing active profile", err)
	}
	public, _ := json.Marshal(inv)
	if bytes.Contains(public, []byte("assword")) || bytes.Contains(public, []byte("phrase")) {
		t.Fatal("public inventory contains credentials")
	}
	edit := s
	edit.Band = "2.4"
	edit.Password = ""
	failNext = true
	if err := m.SaveWiFi(ctx, sampleID, edit); !errors.Is(err, errService) {
		t.Fatal(err)
	}
	_, restored, _ := m.readProfile(sampleID)
	if !bytes.Equal(original, restored) || !active {
		t.Fatal("failed edit did not restore original settings")
	}
	if err := m.SaveWiFi(ctx, sampleID, edit); err != nil {
		t.Fatal(err)
	}
	rec, data, _ := m.readProfile(sampleID)
	pwd, _ := unescapeValue(keyValues(data)["wifi-security.psk"])
	if rec.Band != "2.4" || pwd != s.Password {
		t.Fatal("edit lost stored PSK or band")
	}
	if err := m.DeleteWiFi(ctx, sampleID); err != nil || active || loaded {
		t.Fatal("delete failed", err)
	}
	if _, _, err := m.readProfile(sampleID); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted keyfile remains")
	}
}

// TestForeignActiveWiFi refuses to displace an existing administrator-owned uplink.
func TestForeignActiveWiFi(t *testing.T) {
	m := fixtureManager(t)
	m.command = func(_ context.Context, args ...string) (string, error) {
		if !strings.HasSuffix(strings.Join(args, " "), "show --active") {
			t.Fatal("touched network after foreign ownership")
		}
		return "00112233-abcd-4def-8123-0123456789ab:wlan0", nil
	}
	if err := m.SaveWiFi(context.Background(), sampleID, sampleSettings()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

// TestNetworkManagerOffline checks optional real NM keyfile parsing without installing a daemon or touching any network interface.
func TestNetworkManagerOffline(t *testing.T) {
	nm := os.Getenv("HESTIA_NMCLI_OFFLINE")
	if nm == "" {
		t.Skip("set HESTIA_NMCLI_OFFLINE to the extracted nmcli path")
	}
	for _, band := range []string{"2.4", "5"} {
		s := sampleSettings()
		s.Band = band
		cmd := exec.Command(nm, "--offline", "connection", "modify", "connection.autoconnect", "yes")
		cmd.Stdin = bytes.NewReader(renderProfile(sampleID, s))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("NetworkManager rejected %s GHz keyfile: %v", band, err)
		}
		vals := keyValues(out)
		ssid, err := decodeSSID(vals["wifi.ssid"])
		if err != nil || ssid != s.SSID {
			t.Error("NM changed the SSID")
		}
		psk, err := unescapeValue(vals["wifi-security.psk"])
		if err != nil || psk != s.Password {
			t.Error("NM changed the credential")
		}
		if vals["wifi.band"] != map[string]string{"2.4": "bg", "5": "a"}[band] || vals["ipv4.route-table"] == "" || !strings.Contains(vals["ipv4.routing-rule1"], "oif wlan0") || vals["ipv4.ignore-auto-dns"] != "true" {
			t.Error("NM discarded the station band or routing isolation")
		}
	}
}

// TestPrivateProfileOwnership rejects another account's keyfile and any hard link even when both paths are private.
func TestPrivateProfileOwnership(t *testing.T) {
	m := fixtureManager(t)
	path := filepath.Join(m.directory, wifiFilename(sampleID))
	if err := writePrivate(path, renderProfile(sampleID, sampleSettings())); err != nil {
		t.Fatal(err)
	}
	other := m
	other.ownerUID++
	if _, _, err := other.readProfile(sampleID); !errors.Is(err, ErrConflict) {
		t.Fatal("accepted foreign UID")
	}
	if err := os.Link(path, path+".copy"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.readProfile(sampleID); !errors.Is(err, ErrConflict) {
		t.Fatal("accepted hard-linked keyfile")
	}
}

// TestUnknownConnectedWiFi protects a connected interface with no matching active profile in NM.
func TestUnknownConnectedWiFi(t *testing.T) {
	m := fixtureManager(t)
	m.command = func(_ context.Context, args ...string) (string, error) {
		switch {
		case strings.Contains(strings.Join(args, " "), "GENERAL.STATE"):
			return "100 (connected)", nil
		case strings.HasSuffix(strings.Join(args, " "), "show --active"):
			return "", nil
		default:
			t.Fatal("changed an unowned interface")
			return "", ErrConflict
		}
	}
	if err := m.SaveWiFi(context.Background(), sampleID, sampleSettings()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}

// TestSavePreservesConcurrentForeignAssociation simulates an external owner claiming the adapter after loading an edited profile.
func TestSavePreservesConcurrentForeignAssociation(t *testing.T) {
	m := fixtureManager(t)
	path := filepath.Join(m.directory, wifiFilename(sampleID))
	original := renderProfile(sampleID, sampleSettings())
	if err := writePrivate(path, original); err != nil {
		t.Fatal(err)
	}
	loads := 0
	m.command = func(_ context.Context, args ...string) (string, error) {
		cmd := strings.Join(args, " ")
		switch {
		case strings.HasSuffix(cmd, "show --active"):
			if loads == 0 {
				return sampleID + ":wlan0", nil
			}
			return "00112233-abcd-4def-8123-0123456789ab:wlan0", nil
		case strings.Contains(cmd, "UUID,FILENAME"):
			return sampleID + ":" + path, nil
		case strings.Contains(cmd, "GENERAL.STATE"):
			return "100 (connected)", nil
		case cmd == "connection load "+path:
			loads++
			return "", nil
		default:
			t.Fatalf("replaced foreign association with %s", cmd)
			return "", ErrConflict
		}
	}
	settings := sampleSettings()
	settings.Band = "2.4"
	if err := m.SaveWiFi(context.Background(), sampleID, settings); !errors.Is(err, errRestore) {
		t.Fatal(err)
	}
	_, after, err := m.readProfile(sampleID)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("did not restore previous persisted profile", err)
	}
}
