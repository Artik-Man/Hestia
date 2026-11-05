package physical

import (
	"context"
	"errors"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// verifyOwner refuses UUIDs loaded by NM from another keyfile or plugin, including inactive operator-managed profiles.
func (m Manager) verifyOwner(ctx context.Context, id, path string) (bool, error) {
	output, err := m.nm(ctx, "--terse", "--escape", "no", "--fields", "UUID,FILENAME", "connection", "show")
	if err != nil {
		return false, err
	}
	found := false
	for _, line := range strings.Split(output, "\n") {
		uuid, file, ok := strings.Cut(line, ":")
		if ok && uuid == id {
			if file != path || found {
				return false, ErrConflict
			}
			found = true
		}
	}
	return found, nil
}

// enable activates exactly one UUID on one selected adapter and waits for IPv4 configuration to succeed.
func (m Manager) enable(ctx context.Context, id, device string) error {
	_, err := m.nm(ctx, "--wait", "25", "connection", "up", "uuid", id, "ifname", device)
	return err
}

// requireState refuses unmanaged or transitioning interfaces and a live connection whose owner NM cannot identify.
func (m Manager) requireState(ctx context.Context, device, owner string) error {
	state, err := m.nm(ctx, "--get-values", "GENERAL.STATE", "device", "show", device)
	if err != nil {
		return err
	}
	if state == "30 (disconnected)" && owner == "" || state == "100 (connected)" && owner != "" {
		return nil
	}
	return ErrConflict
}

// SaveWiFi persists and activates a selected station profile, restoring the prior keyfile and previously active owned profiles on failure.
func (m Manager) SaveWiFi(ctx context.Context, id string, s panelmodel.WifiConnectionSettings) error {
	if !identifier.MatchString(id) {
		return ErrInvalid
	}
	_, dir := m.paths()
	path := filepath.Join(dir, wifiFilename(id))
	previous, data, err := m.readProfile(id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if previous.Security == "wpa-psk" && s.Security == "wpa-psk" && s.Password == "" {
		s.Password, err = unescapeValue(keyValues(data)["wifi-security.psk"])
		if err != nil {
			return err
		}
	}
	if err := validateSettings(s); err != nil {
		return err
	}
	ports, err := m.interfaces()
	if err != nil {
		return err
	}
	selected := false
	for _, port := range ports {
		if port.InterfaceName == s.InterfaceName && port.Kind == "wifi" {
			selected = true
			break
		}
	}
	if !selected {
		return ErrConflict
	}
	active, err := m.active(ctx)
	if err != nil {
		return err
	}
	oldTarget := active[s.InterfaceName]
	if oldTarget != "" && oldTarget != id {
		if !identifier.MatchString(oldTarget) {
			return ErrConflict
		}
		owner, _, err := m.readProfile(oldTarget)
		if err != nil || owner.InterfaceName != s.InterfaceName {
			return ErrConflict
		}
		known, err := m.verifyOwner(ctx, oldTarget, filepath.Join(dir, wifiFilename(oldTarget)))
		if err != nil || !known {
			return ErrConflict
		}
	}
	if err := m.requireState(ctx, s.InterfaceName, oldTarget); err != nil {
		return err
	}
	present, err := m.verifyOwner(ctx, id, path)
	if err != nil {
		return err
	}
	if present && data == nil {
		return ErrConflict
	}
	if err := writePrivate(path, renderProfile(id, s)); err != nil {
		return err
	}
	if _, err = m.nm(ctx, "connection", "load", path); err == nil {
		current, readErr := m.active(ctx)
		err = readErr
		if err == nil && current[s.InterfaceName] != oldTarget && current[s.InterfaceName] != id {
			err = ErrConflict
		}
		if err == nil {
			err = m.requireState(ctx, s.InterfaceName, current[s.InterfaceName])
		}
		if err == nil {
			err = m.enable(ctx, id, s.InterfaceName)
		}
	}
	if err == nil {
		return nil
	}
	// Rollback outlives the HTTP request. Never remove another UUID or disconnect an unrelated interface.
	recovery, cancel := context.WithTimeout(context.Background(), 65*time.Second)
	defer cancel()
	if m.restore(recovery, path, id, data) != nil {
		return errRestore
	}
	if data != nil && active[previous.InterfaceName] == id {
		if m.restoreActive(recovery, id, previous.InterfaceName, id) != nil {
			return errRestore
		}
	}
	if oldTarget != "" && oldTarget != id {
		if m.restoreActive(recovery, oldTarget, s.InterfaceName, id) != nil {
			return errRestore
		}
	}
	return err
}

// restoreActive reactivates an original owned profile unless an independent operator has claimed the target since the failed save.
func (m Manager) restoreActive(ctx context.Context, id, device, attempt string) error {
	active, err := m.active(ctx)
	if err != nil {
		return err
	}
	if active[device] != "" && active[device] != id && active[device] != attempt {
		return ErrConflict
	}
	if active[device] == "" {
		if err := m.requireState(ctx, device, ""); err != nil {
			return err
		}
	}
	return m.enable(ctx, id, device)
}

// restore replaces the previous keyfile or removes a newly loaded transient profile after failed activation.
func (m Manager) restore(ctx context.Context, path, id string, previous []byte) error {
	if previous != nil {
		if err := writePrivate(path, previous); err != nil {
			return err
		}
		_, err := m.nm(ctx, "connection", "load", path)
		return err
	}
	loaded, err := m.verifyOwner(ctx, id, path)
	if err != nil {
		return err
	}
	if loaded {
		if _, err := m.nm(ctx, "--wait", "10", "connection", "delete", "uuid", id); err != nil {
			return err
		}
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// DeleteWiFi removes only a validated owned profile. NetworkManager releases that profile's Wi-Fi link and policy routes.
func (m Manager) DeleteWiFi(ctx context.Context, id string) error {
	if !identifier.MatchString(id) {
		return ErrInvalid
	}
	if _, _, err := m.readProfile(id); err != nil {
		return err
	}
	_, dir := m.paths()
	path := filepath.Join(dir, wifiFilename(id))
	return m.restore(ctx, path, id, nil)
}
