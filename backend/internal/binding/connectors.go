package binding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

var ErrInvalidConnector = errors.New("invalid WireGuard connector change")

type connectorProfile struct {
	Name        string   `json:"name,omitempty"`
	Underlays   []string `json:"underlays,omitempty"`
	Slot        int      `json:"slot,omitempty"`
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Group       string   `json:"group"`
	Priority    int      `json:"priority"`
	IPv6Blocked bool     `json:"ipv6Blocked"`
	Status      string   `json:"status"`
}

type connectorGroup struct {
	Name        string   `json:"name,omitempty"`
	ID          string   `json:"id"`
	Exits       []string `json:"exits"`
	DefaultExit string   `json:"defaultExit,omitempty"`
}

type storedProfile struct {
	Hysteria2  []storedHysteria2 `json:"hysteria2,omitempty"`
	Version    int               `json:"version"`
	Interfaces []struct {
		ID             string `json:"id"`
		Type           string `json:"type"`
		ConfigFile     string `json:"config_file,omitempty"`
		PrivateKeyFile string `json:"private_key_file,omitempty"`
		BindInterface  string `json:"bind_interface,omitempty"`
	} `json:"interfaces"`
	Inbounds   []json.RawMessage  `json:"inbounds,omitzero"`
	Connectors []connectorProfile `json:"connectors"`
	Groups     []connectorGroup   `json:"groups"`
	Lists      []struct {
		Name  string   `json:"name,omitempty"`
		ID    string   `json:"id"`
		Group string   `json:"group"`
		Masks []string `json:"masks"`
	} `json:"lists"`
	Healthy   map[string]bool `json:"healthy"`
	SocksPort int             `json:"socks_port,omitempty"`
}

// ApplyAWG stages profile metadata and secret files in the binding journal, then activates only after the runtime probe.
func (e Engine) ApplyAWG(ctx context.Context, request panelmodel.AWGSaveRequest, update bool) error {
	if !awg.ValidConnectionID(request.ID) || (request.Name != "" && ValidateGroupName(request.Name) != nil) || !awg.ValidUnderlays(request.ID, request.Underlays) || ((!update || request.Group != "") && !awgID(request.Group)) || request.Priority < 0 {
		return ErrInvalidConnector
	}
	parsed, err := awg.Parse([]byte(request.Profile))
	if err != nil {
		return ErrInvalidConnector
	}
	check := func(data []byte, staged bool) error {
		return checkConnectorSnapshot(data, request.ID, request.Group, update, staged)
	}
	prepare := func(stage string) error {
		if installed, err := e.awgUnitInstalled(); err != nil || !installed {
			return ErrUnavailable
		}
		if err := e.run(ctx, python, "-I", profile, "--validate-managed", e.dir); err != nil {
			return fmt.Errorf("managed profile validation failed: %w", ErrUnavailable)
		}
		if err := stageAWGChange(ctx, e, stage, request, parsed, update); err != nil {
			return fmt.Errorf("AWG profile staging failed: %w", err)
		}
		return nil
	}
	return e.apply(ctx, prepare, check, false)
}

// DeleteAWG removes one connector and its group membership through the same service-and-route journal as profile changes.
func (e Engine) DeleteAWG(ctx context.Context, id string) error {
	if !awg.ValidConnectionID(id) {
		return ErrNotFound
	}
	check := func(data []byte, staged bool) error {
		config, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		found := snapshotHasConnector(config, id)
		if staged {
			if found {
				return ErrUnavailable
			}
			return nil
		}
		if !found {
			return ErrNotFound
		}
		return nil
	}
	prepare := func(stage string) error {
		if err := e.run(ctx, python, "-I", profile, "--validate-managed", e.dir); err != nil {
			return ErrUnavailable
		}
		current, err := readStoredProfile(e.dir)
		if err != nil || current.Version != 2 {
			return ErrNotFound
		}
		index := connectorIndex(current.Connectors, id)
		if index < 0 {
			return ErrNotFound
		}
		if usesUnderlay(current, id) {
			return ErrConflict
		}
		connector := current.Connectors[index]
		if connector.Status == "ready" {
			if installed, err := e.awgUnitInstalled(); err != nil || !installed {
				return ErrUnavailable
			}
		}
		if err := removeGroupExit(current.Groups, connector.Group, id); err != nil {
			return err
		}
		current.Connectors = append(current.Connectors[:index], current.Connectors[index+1:]...)
		delete(current.Healthy, id)
		for i := range current.Connectors {
			remaining := &current.Connectors[i]
			group, priority := groupExitLocation(current.Groups, remaining.ID)
			if group == "" || priority < 1 {
				return ErrUnavailable
			}
			remaining.Group, remaining.Priority = group, priority
			if err := updateStagedMetadata(stage, *remaining); err != nil {
				return err
			}
		}
		if err := os.RemoveAll(filepath.Join(stage, awgTreeName, id)); err != nil {
			return ErrUnavailable
		}
		return compileConnectorGeneration(ctx, e, stage, current)
	}
	return e.apply(ctx, prepare, check, false)
}

// stageAWGChange replaces one staged connector, preserves neighboring runtime assignments, and builds the candidate profile generation.
func stageAWGChange(ctx context.Context, engine Engine, stage string, request panelmodel.AWGSaveRequest, parsed awg.Profile, update bool) error {
	current, err := readStoredProfile(engine.dir)
	if err != nil {
		return ErrUnavailable
	}
	if current.Version == 1 {
		current.Version = 2
		current.Connectors = []connectorProfile{}
	}
	if current.Version != 2 || current.Healthy == nil {
		return ErrUnavailable
	}
	index := connectorIndex(current.Connectors, request.ID)
	if update && index < 0 {
		return ErrNotFound
	}
	if update && request.Name == "" {
		request.Name = current.Connectors[index].Name
	}
	// An omitted preference preserves transports. An explicit empty array restores automatic routing.
	if update && request.Underlays == nil {
		request.Underlays = current.Connectors[index].Underlays
	}
	if !update && index >= 0 {
		return ErrConflict
	}
	if idInProfile(current, request.ID) && index < 0 {
		return ErrConflict
	}
	oldGroup, oldPriority := groupExitLocation(current.Groups, request.ID)
	if update && request.Group == "" {
		request.Group = oldGroup
	}
	groupIndex := connectorGroupIndex(current.Groups, request.Group)
	if groupIndex < 0 {
		return ErrNotFound
	}
	group := &current.Groups[groupIndex]
	priority := int(request.Priority)
	if priority == 0 {
		if update && oldGroup == request.Group {
			priority = oldPriority
		} else {
			priority = len(group.Exits) + 1
		}
	}
	slot, err := allocateConnectorSlot(current.Connectors, request.ID)
	if err != nil {
		return err
	}
	if !update || oldGroup != request.Group || oldPriority != priority {
		if err := removeGroupExitIfPresent(current.Groups, request.ID); err != nil {
			return err
		}
		if priority < 1 || priority > len(group.Exits)+1 {
			return ErrInvalidConnector
		}
		group.Exits = insertExit(group.Exits, priority-1, request.ID)
		if current.Inbounds != nil && (request.Priority != 0 || len(group.Exits) == 1) {
			group.DefaultExit = request.ID
		}
	}
	for i := range current.Connectors {
		old := &current.Connectors[i]
		old.Group, old.Priority = groupExitLocation(current.Groups, old.ID)
		if err := updateStagedMetadata(stage, *old); err != nil {
			return err
		}
	}
	connector := connectorProfile{Name: request.Name, Underlays: request.Underlays, Slot: slot, ID: request.ID, Type: parsed.Protocol, Group: request.Group, Priority: priority, IPv6Blocked: parsed.IPv6Blocked, Status: "ready"}
	current.Healthy[request.ID] = true
	if index >= 0 {
		current.Connectors[index] = connector
	} else {
		current.Connectors = append(current.Connectors, connector)
	}
	if !validUnderlayGraph(current) {
		return ErrInvalidConnector
	}
	metadata := awg.Metadata{Name: request.Name, Underlays: request.Underlays, Slot: slot, ID: request.ID, Group: request.Group, Priority: priority, Status: "ready", IPv6Blocked: parsed.IPv6Blocked, Protocol: parsed.Protocol, IPv4Address: parsed.IPv4Address, DNSIPv4: parsed.DNSIPv4}
	if err := os.MkdirAll(filepath.Join(stage, awgTreeName), 0700); err != nil {
		return ErrUnavailable
	}
	connectorDir := filepath.Join(stage, awgTreeName, request.ID)
	if err := os.RemoveAll(connectorDir); err != nil {
		return ErrUnavailable
	}
	if err := os.Mkdir(connectorDir, 0700); err != nil {
		return ErrUnavailable
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return ErrUnavailable
	}
	if err := writeConnectorFile(filepath.Join(connectorDir, "profile.conf"), parsed.SecretConfig); err != nil {
		return err
	}
	if err := writeConnectorFile(filepath.Join(connectorDir, "metadata.json"), metadataBytes); err != nil {
		return err
	}
	if err := syncDir(connectorDir); err != nil {
		return ErrUnavailable
	}
	if err := syncDir(filepath.Join(stage, awgTreeName)); err != nil {
		return ErrUnavailable
	}
	if err := compileConnectorGeneration(ctx, engine, stage, current); err != nil {
		return fmt.Errorf("AWG candidate compilation failed: %w", err)
	}
	return nil
}

// allocateConnectorSlot preserves the ID's assignment and returns an unused slot under the installer lock.
// Legacy configured profiles may all carry zero, which was reserved only by the ready connector.
func allocateConnectorSlot(connectors []connectorProfile, id string) (int, error) {
	var used [awg.SlotCount]bool
	assigned := -1
	for _, connector := range connectors {
		if connector.Slot < 0 || connector.Slot >= len(used) {
			return 0, ErrUnavailable
		}
		if connector.Status != "ready" && connector.Slot == 0 {
			continue
		}
		if used[connector.Slot] {
			return 0, ErrUnavailable
		}
		used[connector.Slot] = true
		if connector.ID == id {
			assigned = connector.Slot
		}
	}
	if assigned >= 0 {
		return assigned, nil
	}
	for slot, taken := range used {
		if !taken {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("нет свободного интерфейса WireGuard: %w", ErrConflict)
}

// groupExitLocation returns the one group and one-based priority containing an exit, or empty values if absent.
func groupExitLocation(groups []connectorGroup, id string) (string, int) {
	for _, group := range groups {
		for index, exit := range group.Exits {
			if exit == id {
				return group.ID, index + 1
			}
		}
	}
	return "", 0
}

// checkConnectorSnapshot validates the current or candidate group topology for one connector mutation.
func checkConnectorSnapshot(data []byte, id, group string, update, staged bool) error {
	config, err := controller.CheckSnapshot(data)
	if err != nil {
		return ErrUnavailable
	}
	found, targetFound := false, false
	for _, item := range config.Groups {
		if item.ID == group && group != "" {
			targetFound = true
		}
		for _, exit := range item.Exits {
			if exit == id {
				found = true
				if staged && group != "" && item.ID != group {
					return ErrConflict
				}
			}
		}
	}
	if group != "" && !targetFound {
		return ErrNotFound
	}
	if staged {
		if update && !found {
			return ErrUnavailable
		}
		if !update && !found {
			return ErrUnavailable
		}
	} else if update != found {
		if update {
			return ErrNotFound
		}
		return ErrConflict
	}
	return nil
}

// snapshotHasConnector reports whether one connector ID appears in any validated group exit list.
func snapshotHasConnector(config controller.Config, id string) bool {
	for _, group := range config.Groups {
		for _, exit := range group.Exits {
			if exit == id {
				return true
			}
		}
	}
	return false
}

// readStoredProfile decodes one checksum-validated profile schema used by the transaction compiler.
func readStoredProfile(directory string) (storedProfile, error) {
	var profile storedProfile
	data, err := os.ReadFile(filepath.Join(directory, "profile.json"))
	if err != nil {
		return profile, err
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		return profile, err
	}
	if profile.Version != 1 && profile.Version != 2 {
		return profile, ErrUnavailable
	}
	return profile, nil
}

// compileConnectorGeneration writes the candidate source profile, runs the strict compiler, and records generation hashes.
func compileConnectorGeneration(ctx context.Context, engine Engine, stage string, profileValue storedProfile) error {
	profilePath := filepath.Join(stage, "profile.json")
	profileBytes, err := json.MarshalIndent(profileValue, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot serialize source profile: %w", ErrUnavailable)
	}
	if err := writeConnectorFile(profilePath, profileBytes); err != nil {
		return fmt.Errorf("cannot write source profile: %w", err)
	}
	args := []string{"-I", profile, profilePath, stage, stage}
	for _, item := range profileValue.Interfaces {
		if item.Type == "wireguard" {
			args = append(args, engine.dir)
			break
		}
	}
	if err := engine.run(ctx, python, args...); err != nil {
		return fmt.Errorf("profile compiler rejected candidate: %w", ErrInvalidConnector)
	}
	for _, pair := range [][2]string{{"profile.json", "profile-source.sha256"}, {"sing-box.json", "profile-backend.sha256"}} {
		data, err := os.ReadFile(filepath.Join(stage, pair[0]))
		if err != nil {
			return fmt.Errorf("profile compiler did not create %s: %w", pair[0], ErrUnavailable)
		}
		digest := sha256.Sum256(data)
		if err := writeConnectorFile(filepath.Join(stage, pair[1]), []byte(hex.EncodeToString(digest[:])+"\n")); err != nil {
			return fmt.Errorf("cannot write generation digest %s: %w", pair[1], err)
		}
	}
	return nil
}

// writeConnectorFile creates one exclusive private staging file and durably flushes its bytes.
func writeConnectorFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// connectorGroupIndex finds one stable target group ID in the versioned profile.
func connectorGroupIndex(groups []connectorGroup, id string) int {
	for i := range groups {
		if groups[i].ID == id {
			return i
		}
	}
	return -1
}

// connectorIndex finds one stored connector by stable ID.
func connectorIndex(connectors []connectorProfile, id string) int {
	for i := range connectors {
		if connectors[i].ID == id {
			return i
		}
	}
	return -1
}

// idInProfile detects collisions with groups and ordinary WireGuard exits.
func idInProfile(profile storedProfile, id string) bool {
	for _, group := range profile.Groups {
		if group.ID == id {
			return true
		}
	}
	for _, item := range profile.Interfaces {
		if item.ID == id {
			return true
		}
	}
	return false
}

// removeGroupExitIfPresent removes a connector from any prior group before it is reinserted at its new priority.
func removeGroupExitIfPresent(groups []connectorGroup, id string) error {
	for i := range groups {
		for index, exit := range groups[i].Exits {
			if exit == id {
				groups[i].Exits = append(groups[i].Exits[:index], groups[i].Exits[index+1:]...)
				if groups[i].DefaultExit == id {
					groups[i].DefaultExit = "deny"
					if len(groups[i].Exits) > 0 {
						groups[i].DefaultExit = groups[i].Exits[0]
					}
				}
				return nil
			}
		}
	}
	return nil
}

// removeGroupExit removes one known connector from its owning group or reports an inconsistent profile.
func removeGroupExit(groups []connectorGroup, group, id string) error {
	index := connectorGroupIndex(groups, group)
	if index < 0 {
		return ErrUnavailable
	}
	for exitIndex, exit := range groups[index].Exits {
		if exit == id {
			groups[index].Exits = append(groups[index].Exits[:exitIndex], groups[index].Exits[exitIndex+1:]...)
			if groups[index].DefaultExit == id {
				groups[index].DefaultExit = "deny"
				if len(groups[index].Exits) > 0 {
					groups[index].DefaultExit = groups[index].Exits[0]
				}
			}
			return nil
		}
	}
	return ErrUnavailable
}

// insertExit inserts one unique connector at its validated zero-based position.
func insertExit(exits []string, index int, id string) []string {
	exits = append(exits, "")
	copy(exits[index+1:], exits[index:])
	exits[index] = id
	return exits
}

// updateStagedMetadata synchronizes one staged connector's group, priority and lifecycle state without changing its secret profile.
func updateStagedMetadata(stage string, connector connectorProfile) error {
	path := filepath.Join(stage, awgTreeName, connector.ID, "metadata.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ErrUnavailable
	}
	var metadata awg.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.ID != connector.ID {
		return ErrUnavailable
	}
	metadata.Group, metadata.Priority, metadata.Status = connector.Group, connector.Priority, connector.Status
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return ErrUnavailable
	}
	temporary := path + ".next"
	if err := writeConnectorFile(temporary, encoded); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return ErrUnavailable
	}
	return nil
}

// ReadAWGProfile returns the normalized settings and keys of one committed profile under the installer's shared lock.
func (e Engine) ReadAWGProfile(id string) (panelmodel.AWGConnectionProfile, error) {
	var result panelmodel.AWGConnectionProfile
	if !awg.ValidConnectionID(id) {
		return result, ErrNotFound
	}
	lock, err := e.acquire(false)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	if err := e.validateInstallation(); err != nil {
		return result, err
	}
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		return result, ErrUnavailable
	}
	root := filepath.Join(e.dir, awgTreeName)
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return result, ErrNotFound
	}
	if err := privateDirectory(root); err != nil {
		return result, err
	}
	path := filepath.Join(root, id)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return result, ErrNotFound
	}
	var total int64
	metadata, profile, err := readAWGDirectory(path, id, &total)
	if err != nil {
		return result, err
	}
	return panelmodel.AWGConnectionProfile{Name: metadata.DisplayName(), Underlays: metadata.Underlays, ID: metadata.ID, Group: metadata.Group, Priority: metadata.Priority, Profile: string(profile.SecretConfig)}, nil
}
