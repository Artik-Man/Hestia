package binding

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/network"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// PhysicalManager supplies host observations and limits mutations to Hestia-owned NetworkManager profiles.
type PhysicalManager = network.Physical

var wifiID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// PhysicalConnections combines kernel observations and configured direct bindings under a shared install lock.
func (e Engine) PhysicalConnections(ctx context.Context, manager PhysicalManager) (panelmodel.PhysicalInventory, error) {
	var inventory panelmodel.PhysicalInventory
	lock, err := e.acquire(false)
	if err != nil {
		return inventory, err
	}
	defer lock.Close()
	profile, err := e.physicalProfile()
	if err != nil {
		return inventory, err
	}
	inventory, err = manager.Inventory(ctx)
	if err != nil {
		return inventory, err
	}
	index := map[string]int{}
	for i := range inventory.Interfaces {
		device := &inventory.Interfaces[i]
		if device.ExitIDs == nil {
			device.ExitIDs = []string{}
		}
		index[device.InterfaceName] = i
	}
	for _, item := range profile.Interfaces {
		if item.Type != "direct" || item.BindInterface == "" {
			continue
		}
		i, ok := index[item.BindInterface]
		if !ok {
			i = len(inventory.Interfaces)
			index[item.BindInterface] = i
			kind := "ethernet"
			if slices.ContainsFunc(inventory.WifiProfiles, func(p panelmodel.WifiConnection) bool { return p.InterfaceName == item.BindInterface }) {
				kind = "wifi"
			}
			inventory.Interfaces = append(inventory.Interfaces, panelmodel.PhysicalInterface{InterfaceName: item.BindInterface, Kind: kind})
		}
		inventory.Interfaces[i].ExitIDs = append(inventory.Interfaces[i].ExitIDs, item.ID)
	}
	if inventory.Interfaces == nil {
		inventory.Interfaces = []panelmodel.PhysicalInterface{}
	}
	if inventory.WifiProfiles == nil {
		inventory.WifiProfiles = []panelmodel.WifiConnection{}
	}
	return inventory, nil
}

// physicalProfile reads a committed managed profile while the caller owns the installer lock.
func (e Engine) physicalProfile() (storedProfile, error) {
	if err := e.validateInstallation(); err != nil {
		return storedProfile{}, err
	}
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		return storedProfile{}, ErrConflict
	}
	if _, err := e.managedInfo(e.dir, "profile.json", true); err != nil {
		return storedProfile{}, err
	}
	return readStoredProfile(e.dir)
}

// ChangeWifi serializes profile creation, update and removal and verifies ownership before invoking the host backend.
// An empty ID creates a profile, and nil settings remove an existing identified profile.
func (e Engine) ChangeWifi(ctx context.Context, manager PhysicalManager, id string, settings *panelmodel.WifiConnectionSettings) error {
	create := id == ""
	if create && settings == nil || !create && !wifiID.MatchString(id) {
		return ErrInvalidOrder
	}
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err := e.physicalProfile(); err != nil {
		return err
	}
	inventory, err := manager.Inventory(ctx)
	if err != nil {
		return err
	}
	if !inventory.WifiAvailable {
		return ErrUnavailable
	}
	if create {
		var raw [16]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return ErrUnavailable
		}
		raw[6] = raw[6]&0x0f | 0x40
		raw[8] = raw[8]&0x3f | 0x80
		id = fmt.Sprintf("%x-%x-%x-%x-%x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:])
	}
	found := slices.ContainsFunc(inventory.WifiProfiles, func(w panelmodel.WifiConnection) bool { return w.ID == id })
	if create && found {
		return ErrConflict
	}
	if !create && !found {
		return ErrNotFound
	}
	if settings == nil {
		return manager.DeleteWiFi(ctx, id)
	}
	return manager.SaveWiFi(ctx, id, *settings)
}
