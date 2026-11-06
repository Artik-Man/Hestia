package awg

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/storage"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SlotCount bounds the tunnel range below Linux reserved route tables.
const SlotCount = network.SlotCount

const (
	profileFile  = "profile.conf"
	metadataFile = "metadata.json"
)

// Metadata is the non-secret public description persisted for one configured connector.
type Metadata struct {
	Name        string   `json:"name,omitempty"`
	Underlays   []string `json:"underlays,omitempty"`
	Slot        int      `json:"slot,omitempty"`
	ID          string   `json:"id"`
	Group       string   `json:"group"`
	Priority    int      `json:"priority"`
	Status      string   `json:"status"`
	IPv6Blocked bool     `json:"ipv6Blocked"`
	Protocol    string   `json:"type"`
	IPv4Address string   `json:"ipv4Address"`
	DNSIPv4     string   `json:"dnsIPv4"`
}

// DisplayName returns the saved label or the original label of a profile created before names were stored separately.
func (m Metadata) DisplayName() string {
	if m.Name == "" {
		return m.ID
	}
	return m.Name
}

// Store persists normalized profiles and public metadata in private per-connector directories.
// The directory must be writable only by the privileged Hestia helper.
type Store struct {
	directory string
	lockPath  string
}

// OpenStore creates or validates a private AWG store directory and recovers interrupted swaps.
func OpenStore(directory string) (*Store, error) {
	lockPath := filepath.Join(filepath.Dir(directory), ".awg-store.lock")
	lock, err := storage.OpenFile(lockPath, storage.Create|storage.ReadWrite|storage.NoFollow, 0600)
	if err != nil {
		return nil, errors.New("cannot prepare AWG store lock")
	}
	if err := lock.Close(); err != nil {
		return nil, errors.New("cannot prepare AWG store lock")
	}
	return OpenStoreWithLock(directory, lockPath)
}

// OpenStoreWithLock creates or validates a private AWG store and serializes access with the supplied transaction lock.
func OpenStoreWithLock(directory, lockPath string) (*Store, error) {
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode()&os.ModeSymlink != 0 || lockInfo.Mode().Perm()&0022 != 0 {
		return nil, errors.New("cannot validate AWG store lock")
	}
	lockStat, ok := storage.Stat(lockInfo)
	if !ok || int(lockStat.Uid) != os.Geteuid() || lockStat.Nlink != 1 {
		return nil, errors.New("cannot validate AWG store lock")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("cannot prepare AWG profile storage")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid AWG profile storage directory")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, errors.New("cannot secure AWG profile storage")
	}
	store := &Store{directory: directory, lockPath: lockPath}
	if err := store.readDirectory(func([]os.DirEntry) error { return nil }); err != nil {
		return nil, err
	}
	return store, nil
}

// Save validates and atomically replaces one connector directory with root-only config and metadata.
func (s *Store) Save(metadata Metadata, raw []byte) error {
	if !ValidConnectionID(metadata.ID) || !ValidUnderlays(metadata.ID, metadata.Underlays) || !identifierPattern.MatchString(metadata.Group) || metadata.Priority < 1 || metadata.Slot < 0 || metadata.Slot >= SlotCount {
		return errors.New("invalid AWG connection metadata")
	}
	profile, err := Parse(raw)
	if err != nil {
		return err
	}
	metadata.IPv6Blocked = profile.IPv6Blocked
	metadata.Status = "configured"
	metadata.Protocol = profile.Protocol
	metadata.IPv4Address = profile.IPv4Address
	metadata.DNSIPv4 = profile.DNSIPv4
	return s.withLock(storage.LockExclusive, func() error {
		return s.replace(metadata, profile.SecretConfig)
	})
}

// List returns sorted public metadata without reading or returning private profiles.
func (s *Store) List() ([]Metadata, error) {
	var result []Metadata
	err := s.readDirectory(func(entries []os.DirEntry) error {
		for _, entry := range entries {
			if !entry.IsDir() || !ValidConnectionID(entry.Name()) {
				continue
			}
			metadata, err := s.readMetadata(entry.Name())
			if err != nil {
				return err
			}
			result = append(result, metadata)
		}
		return nil
	})
	return result, err
}

// Load returns the non-secret metadata and normalized secret config for a privileged runtime caller.
func (s *Store) Load(id string) (Metadata, []byte, error) {
	var metadata Metadata
	var config []byte
	if !ValidConnectionID(id) {
		return metadata, nil, errors.New("invalid AWG connection ID")
	}
	err := s.withLock(storage.LockExclusive, func() error {
		if err := s.recover(); err != nil {
			return err
		}
		var err error
		metadata, err = s.readMetadata(id)
		if err != nil {
			return err
		}
		path := filepath.Join(s.directory, id, profileFile)
		data, err := readPrivateFile(path, maxProfileBytes)
		if err != nil {
			return errors.New("cannot read AWG profile")
		}
		if _, err := Parse(data); err != nil {
			return errors.New("stored AWG profile failed validation")
		}
		config = data
		return nil
	})
	return metadata, config, err
}

// LoadReadyForRuntime reads the requested committed-ready connector (or the sole ready connector for legacy callers) for the root AWG service while the installer lock is held by its launcher.
func (s *Store) LoadReadyForRuntime(ids ...string) (Metadata, []byte, error) {
	var selected Metadata
	var profile []byte
	if len(ids) > 1 || (len(ids) == 1 && !ValidConnectionID(ids[0])) {
		return selected, nil, errors.New("invalid AWG runtime identity")
	}
	info, err := os.Lstat(s.directory)
	if err != nil || info == nil {
		return selected, nil, errors.New("AWG runtime storage is unavailable")
	}
	stat, ok := storage.Stat(info)
	if !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 || !ok || int(stat.Uid) != os.Geteuid() {
		return selected, nil, errors.New("AWG runtime storage is unavailable")
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return selected, nil, errors.New("AWG runtime storage is unavailable")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !ValidConnectionID(entry.Name()) || (len(ids) == 1 && entry.Name() != ids[0]) {
			continue
		}
		metadata, err := s.readMetadata(entry.Name())
		if err != nil {
			return Metadata{}, nil, err
		}
		if metadata.Status != "ready" {
			continue
		}
		if selected.ID != "" {
			return Metadata{}, nil, errors.New("multiple AWG connectors are marked ready")
		}
		selected = metadata
	}
	if selected.ID == "" {
		return Metadata{}, nil, errors.New("no ready AWG connector is configured")
	}
	profile, err = readPrivateFile(filepath.Join(s.directory, selected.ID, profileFile), maxProfileBytes)
	if err != nil {
		return Metadata{}, nil, errors.New("ready AWG profile is unavailable")
	}
	parsed, err := Parse(profile)
	if err != nil || parsed.Protocol != selected.Protocol || parsed.IPv4Address != selected.IPv4Address || parsed.DNSIPv4 != selected.DNSIPv4 || parsed.IPv6Blocked != selected.IPv6Blocked {
		return Metadata{}, nil, errors.New("ready AWG profile failed validation")
	}
	return selected, profile, nil
}

// Delete atomically removes one configured connection, restoring it if the directory swap fails.
func (s *Store) Delete(id string) error {
	if !ValidConnectionID(id) {
		return errors.New("invalid AWG connection ID")
	}
	return s.withLock(storage.LockExclusive, func() error {
		if err := s.recover(); err != nil {
			return err
		}
		if _, err := s.readMetadata(id); err != nil {
			return err
		}
		path := filepath.Join(s.directory, id)
		tombstone := s.deletePath(id)
		if err := os.Rename(path, tombstone); err != nil {
			return errors.New("cannot stage AWG profile removal")
		}
		if err := syncDirectory(s.directory); err != nil {
			_ = os.Rename(tombstone, path)
			return errors.New("cannot confirm AWG profile removal")
		}
		if err := os.RemoveAll(tombstone); err != nil {
			return errors.New("AWG profile removal is pending recovery")
		}
		return syncDirectory(s.directory)
	})
}

// replace stages metadata and config, swaps the directory, and restores the prior directory on failure.
func (s *Store) replace(metadata Metadata, config []byte) error {
	stage, err := os.MkdirTemp(s.directory, ".stage-")
	if err != nil {
		return errors.New("cannot stage AWG profile")
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0700); err != nil {
		return errors.New("cannot secure AWG staging directory")
	}
	if err := writeExclusive(filepath.Join(stage, profileFile), config, 0600); err != nil {
		return errors.New("cannot stage AWG profile")
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		return errors.New("cannot encode AWG metadata")
	}
	if err := writeExclusive(filepath.Join(stage, metadataFile), metadataBytes, 0600); err != nil {
		return errors.New("cannot stage AWG metadata")
	}
	if err := syncDirectory(stage); err != nil {
		return errors.New("cannot confirm staged AWG profile")
	}
	path, backup := filepath.Join(s.directory, metadata.ID), s.backupPath(metadata.ID)
	if _, err := os.Lstat(path); err == nil {
		if err := os.Rename(path, backup); err != nil {
			return errors.New("cannot stage previous AWG profile")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect previous AWG profile")
	}
	if err := os.Rename(stage, path); err != nil {
		if _, backupErr := os.Lstat(backup); backupErr == nil {
			_ = os.Rename(backup, path)
		}
		return errors.New("cannot publish AWG profile")
	}
	if err := syncDirectory(s.directory); err != nil {
		_ = os.RemoveAll(path)
		_ = os.Rename(backup, path)
		return errors.New("cannot confirm AWG profile publication")
	}
	if err := os.RemoveAll(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("AWG profile publication is pending recovery")
	}
	return syncDirectory(s.directory)
}

// readMetadata reads a bounded metadata object and rejects identity mismatches and secret fields.
func (s *Store) readMetadata(id string) (Metadata, error) {
	var metadata Metadata
	path := filepath.Join(s.directory, id, metadataFile)
	data, err := readPrivateFile(path, 8192)
	if err != nil {
		return metadata, errors.New("AWG connection not found or unreadable")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || decoder.Decode(new(any)) != io.EOF || metadata.ID != id || !ValidUnderlays(id, metadata.Underlays) || !identifierPattern.MatchString(metadata.Group) || metadata.Priority < 1 || metadata.Slot < 0 || metadata.Slot >= SlotCount || (metadata.Status != "configured" && metadata.Status != "ready") || (metadata.Protocol != "wireguard" && metadata.Protocol != "amneziawg") || metadata.IPv4Address == "" || metadata.DNSIPv4 == "" {
		return Metadata{}, errors.New("stored AWG metadata is invalid")
	}
	return metadata, nil
}

// recover restores a backup when an interrupted write left no published profile and removes stale backups otherwise.
func (s *Store) recover() error {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return errors.New("cannot recover AWG storage")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".delete-") {
			id := strings.TrimPrefix(name, ".delete-")
			if !ValidConnectionID(id) || !entry.IsDir() {
				return errors.New("invalid AWG deletion recovery entry")
			}
			if err := os.RemoveAll(filepath.Join(s.directory, name)); err != nil {
				return errors.New("cannot finish AWG profile removal")
			}
			continue
		}
		if !strings.HasPrefix(name, ".backup-") {
			continue
		}
		id := strings.TrimPrefix(name, ".backup-")
		if !ValidConnectionID(id) || !entry.IsDir() {
			return errors.New("invalid AWG recovery entry")
		}
		backup, target := filepath.Join(s.directory, name), filepath.Join(s.directory, id)
		if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(backup, target); err != nil {
				return errors.New("cannot restore previous AWG profile")
			}
		} else if err != nil {
			return errors.New("cannot inspect AWG recovery target")
		} else if err := os.RemoveAll(backup); err != nil {
			return errors.New("cannot remove stale AWG backup")
		}
	}
	return syncDirectory(s.directory)
}

// backupPath returns the fixed sibling backup path for one validated connector ID.
func (s *Store) backupPath(id string) string { return filepath.Join(s.directory, ".backup-"+id) }

// deletePath returns the fixed sibling tombstone path for one validated connector ID.
func (s *Store) deletePath(id string) string { return filepath.Join(s.directory, ".delete-"+id) }

// readDirectory runs read under a shared installer lock when the store is clean.
// After an interrupted write it reacquires an exclusive lock, recovers the
// current state, and supplies fresh entries while still holding that lock.
func (s *Store) readDirectory(read func([]os.DirEntry) error) error {
	var recoveryNeeded bool
	err := s.withLock(storage.LockShared, func() error {
		entries, err := os.ReadDir(s.directory)
		if err != nil {
			return errors.New("cannot inspect AWG storage")
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".backup-") || strings.HasPrefix(entry.Name(), ".delete-") {
				recoveryNeeded = true
				return nil
			}
		}
		return read(entries)
	})
	if err != nil || !recoveryNeeded {
		return err
	}
	return s.withLock(storage.LockExclusive, func() error {
		if err := s.recover(); err != nil {
			return err
		}
		entries, err := os.ReadDir(s.directory)
		if err != nil {
			return errors.New("cannot inspect recovered AWG storage")
		}
		return read(entries)
	})
}

// withLock takes the specified shared or exclusive installer lock and excludes pending binding transactions.
func (s *Store) withLock(mode storage.LockMode, operation func() error) error {
	file, err := storage.OpenFile(s.lockPath, storage.ReadWrite|storage.NoFollow, 0)
	if err != nil {
		return errors.New("cannot lock AWG storage")
	}
	defer file.Close()
	if err := storage.Flock(file, mode); err != nil {
		return errors.New("cannot lock AWG storage")
	}
	defer storage.Flock(file, storage.LockUnlock)
	if _, err := os.Lstat(filepath.Join(filepath.Dir(s.directory), ".binding-pending")); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("AWG store is unavailable during a pending profile transaction")
	}
	return operation()
}

// writeExclusive creates a file with the requested permissions and confirms its bytes are durable.
func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

// readPrivateFile reads a regular non-symlink file within a strict size bound.
func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := storage.OpenFile(path, storage.ReadOnly|storage.NoFollow|storage.CloseOnExec, 0)
	if err != nil {
		return nil, errors.New("unsafe private file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("unsafe private file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read private file")
	}
	return data, nil
}

// syncDirectory flushes directory entry changes before the operation reports success.
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// ValidUnderlays validates a bounded ordered list of distinct exit IDs and rejects a self reference.
func ValidUnderlays(id string, choices []string) bool {
	if len(choices) > 64 {
		return false
	}
	seen := make(map[string]bool, len(choices))
	for _, candidate := range choices {
		if !ValidConnectionID(candidate) || candidate == id || seen[candidate] {
			return false
		}
		seen[candidate] = true
	}
	return true
}
