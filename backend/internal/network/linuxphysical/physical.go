// Package linuxphysical discovers Linux Ethernet and Wi-Fi interfaces and manages Hestia-owned Wi-Fi station profiles.
package linuxphysical

import (
	"context"
	"errors"
	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/storage"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid  = network.ErrInvalid
	ErrConflict = network.ErrConflict
	ErrNotFound = network.ErrNotFound
	errService  = errors.New("wireless network manager unavailable")
	errRestore  = errors.New("wireless network configuration could not be restored")
	identifier  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	deviceName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`)
)

// Manager uses the kernel sysfs inventory and the persistent root-only NetworkManager keyfile directory.
// Its zero value selects the system paths. Mutations must be serialized by the caller's installation lock.
type Manager struct {
	sysfs, directory string
	ownerUID         uint32
	command          func(context.Context, ...string) (string, error)
}

// paths returns the system locations unless isolated fixtures were provided.
func (m Manager) paths() (string, string) {
	sys, dir := m.sysfs, m.directory
	if sys == "" {
		sys = "/sys/class/net"
	}
	if dir == "" {
		dir = storage.Installed().NetworkProfiles
	}
	return sys, dir
}

// nm runs NetworkManager without a shell or secret arguments, and never exposes its stderr to the API.
func (m Manager) nm(ctx context.Context, args ...string) (string, error) {
	if m.command != nil {
		return m.command(ctx, args...)
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/nmcli", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return "", errService
	}
	return strings.TrimSpace(string(output)), nil
}

// CarrierStateAt returns the observed Linux carrier state for a validated kernel device name.
// It reports unknown when the device name or sysfs observation is unavailable or malformed.
func CarrierStateAt(sysfs, name string) panelmodel.CarrierState {
	if !deviceName.MatchString(name) {
		return panelmodel.CarrierUnknown
	}
	data, err := os.ReadFile(filepath.Join(sysfs, name, "carrier"))
	if err != nil {
		return panelmodel.CarrierUnknown
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return panelmodel.CarrierUp
	case "0":
		return panelmodel.CarrierDown
	default:
		return panelmodel.CarrierUnknown
	}
}

// CarrierAt reports true only when Linux explicitly reports an active link on the named device.
func CarrierAt(sysfs, name string) bool {
	return CarrierStateAt(sysfs, name) == panelmodel.CarrierUp
}

// interfaces reports only Ethernet-type kernel interfaces with backing hardware; unplugged devices remain visible.
func (m Manager) interfaces() ([]panelmodel.PhysicalInterface, error) {
	sys, _ := m.paths()
	dirs, err := os.ReadDir(sys)
	if err != nil {
		return nil, err
	}
	list := []panelmodel.PhysicalInterface{}
	for _, entry := range dirs {
		name := entry.Name()
		if !deviceName.MatchString(name) {
			continue
		}
		base := filepath.Join(sys, name)
		if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
			continue
		}
		typ, err := os.ReadFile(filepath.Join(base, "type"))
		if err != nil || strings.TrimSpace(string(typ)) != "1" {
			continue
		}
		kind := "ethernet"
		for _, attr := range []string{"phy80211", "wireless"} {
			if _, err := os.Stat(filepath.Join(base, attr)); err == nil {
				kind = "wifi"
				break
			}
		}
		carrier := CarrierStateAt(sys, name)
		list = append(list, panelmodel.PhysicalInterface{InterfaceName: name, Kind: kind, Present: true, CarrierState: carrier, Online: carrier == panelmodel.CarrierUp, ExitIDs: []string{}})
	}
	return list, nil
}

// KernelInventory returns physical Linux network devices without consulting NetworkManager or loading saved profiles.
func (m Manager) KernelInventory() ([]panelmodel.PhysicalInterface, error) {
	return m.interfaces()
}

// active returns active UUIDs keyed by kernel interface; an empty mapping distinguishes a free adapter from a failed NM query.
func (m Manager) active(ctx context.Context) (map[string]string, error) {
	out, err := m.nm(ctx, "--terse", "--fields", "UUID,DEVICE", "connection", "show", "--active")
	if err != nil {
		return nil, err
	}
	active := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		uuid, dev, ok := strings.Cut(line, ":")
		if ok && dev != "" && dev != "--" {
			active[dev] = uuid
		}
	}
	return active, nil
}

// Inventory reads public profile fields and current carrier/activation status, including on gateways without NetworkManager.
func (m Manager) Inventory(ctx context.Context) (panelmodel.PhysicalInventory, error) {
	var result panelmodel.PhysicalInventory
	ports, err := m.interfaces()
	if err != nil {
		return result, err
	}
	result.Interfaces = ports
	result.WifiProfiles = []panelmodel.WifiConnection{}
	probe, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	active, err := m.active(probe)
	result.WifiAvailable = err == nil
	_, dir := m.paths()
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	for _, entry := range entries {
		name := entry.Name()
		id := strings.TrimSuffix(strings.TrimPrefix(name, "hestia-wifi-"), ".nmconnection")
		if !identifier.MatchString(id) || name != wifiFilename(id) {
			continue
		}
		record, _, err := m.readProfile(id)
		if err != nil {
			return result, err
		}
		record.Active = active[record.InterfaceName] == id
		result.WifiProfiles = append(result.WifiProfiles, record)
	}
	return result, nil
}

// wifiFilename returns the fixed path component for an already validated profile UUID.
func wifiFilename(id string) string { return "hestia-wifi-" + id + ".nmconnection" }

// Online returns true only when sysfs explicitly confirms an active link for the kernel device name.
func (m Manager) Online(device string) bool { sys, _ := m.paths(); return CarrierAt(sys, device) }

// State returns the sysfs link observation without collapsing an unreadable carrier into link down.
func (m Manager) State(device string) panelmodel.CarrierState {
	sys, _ := m.paths()
	return CarrierStateAt(sys, device)
}

var _ network.Physical = Manager{}
var _ network.Carrier = Manager{}
