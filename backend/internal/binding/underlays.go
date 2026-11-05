package binding

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// validUnderlayGraph checks every stored dependency against this generation and rejects cycles through any backup exit.
func validUnderlayGraph(profile storedProfile) bool {
	deps := make(map[string][]string, len(profile.Interfaces)+len(profile.Connectors))
	for _, item := range profile.Interfaces {
		deps[item.ID] = nil
	}
	for _, item := range profile.Connectors {
		if !awg.ValidUnderlays(item.ID, item.Underlays) {
			return false
		}
		deps[item.ID] = item.Underlays
	}
	const (
		visiting = 1
		complete = 2
	)
	state := make(map[string]int, len(deps))
	var visit func(string) bool
	visit = func(id string) bool {
		edges, ok := deps[id]
		if !ok || state[id] == visiting {
			return false
		}
		if state[id] == complete {
			return true
		}
		state[id] = visiting
		for _, target := range edges {
			if !visit(target) {
				return false
			}
		}
		state[id] = complete
		return true
	}
	for id := range deps {
		if !visit(id) {
			return false
		}
	}
	return true
}

// UnderlayCandidates reads public routing IDs, types and display names from the locked committed generation.
func (e Engine) UnderlayCandidates() ([]panelmodel.AWGUnderlayCandidate, error) {
	lock, err := e.acquire(false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	return e.connectionCatalog()
}

// connectionCatalog reads typed public exits and display names while the caller holds the installer lock.
func (e Engine) connectionCatalog() ([]panelmodel.AWGUnderlayCandidate, error) {
	if err := e.validateInstallation(); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	if _, err := e.managedInfo(e.dir, "profile.json", true); err != nil {
		return nil, err
	}
	profile, err := readStoredProfile(e.dir)
	if err != nil {
		return nil, ErrUnavailable
	}
	names, err := e.directNames()
	if err != nil {
		return nil, err
	}
	candidates := make([]panelmodel.AWGUnderlayCandidate, 0, len(profile.Interfaces)+len(profile.Connectors))
	for _, item := range profile.Interfaces {
		if !awgID(item.ID) || (item.Type != "wireguard" && item.Type != "direct") {
			return nil, ErrUnavailable
		}
		name := ""
		if item.Type == "direct" {
			name = names[item.ID]
		}
		candidates = append(candidates, panelmodel.AWGUnderlayCandidate{ID: item.ID, Type: item.Type, Name: name})
	}
	for _, item := range profile.Connectors {
		if !awg.ValidConnectionID(item.ID) || (item.Name != "" && ValidateGroupName(item.Name) != nil) || (item.Type != "wireguard" && item.Type != "amneziawg") {
			return nil, ErrUnavailable
		}
		name := item.Name
		if name == "" {
			name = item.ID
		}
		candidates = append(candidates, panelmodel.AWGUnderlayCandidate{ID: item.ID, Type: item.Type, Name: name})
	}
	return candidates, nil
}

const directNamesFile = "direct-connection-names.json"

// directNames loads bounded, owner-only display metadata, accepting older installations without a name file.
func (e Engine) directNames() (map[string]string, error) {
	path := filepath.Join(e.dir, directNamesFile)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	info, err := e.managedInfo(e.dir, directNamesFile, true)
	if err != nil || info.Size() > 1<<20 {
		return nil, ErrUnavailable
	}
	var names map[string]string
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &names) != nil || names == nil {
		return nil, ErrUnavailable
	}
	for id, name := range names {
		if !awgID(id) || ValidateGroupName(name) != nil {
			return nil, ErrUnavailable
		}
	}
	return names, nil
}

// RenameDirectConnection verifies the current exit type under the installer lock and durably replaces display metadata only.
func (e Engine) RenameDirectConnection(id, name string) error {
	if !awgID(id) || ValidateGroupName(name) != nil {
		return ErrInvalidOrder
	}
	lock, err := e.acquire(true)
	if err != nil {
		return err
	}
	defer lock.Close()
	catalog, err := e.connectionCatalog()
	if err != nil {
		return err
	}
	names := map[string]string{}
	found := false
	for _, item := range catalog {
		if item.ID == id {
			if item.Type != "direct" {
				return ErrConflict
			}
			found = true
		}
		if item.Type == "direct" && item.Name != "" {
			names[item.ID] = item.Name
		}
	}
	if !found {
		return ErrNotFound
	}
	names[id] = name
	data, err := json.Marshal(names)
	if err != nil || len(data) > 1<<20 {
		return ErrUnavailable
	}
	temp, err := os.CreateTemp(e.dir, ".direct-names-")
	if err != nil {
		return ErrUnavailable
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(data); err == nil {
		err = temp.Sync()
	}
	if errors.Join(err, temp.Close()) != nil || os.Rename(temp.Name(), filepath.Join(e.dir, directNamesFile)) != nil {
		return ErrUnavailable
	}
	return syncDir(e.dir)
}
