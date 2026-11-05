package binding

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Artik-Man/Hestia/internal/awg"
)

const awgTreeName = "awg"

type awgStoredMetadata = awg.Metadata

// stageAWGTree copies the committed private connector tree into a transaction stage before any candidate edits.
func (e Engine) stageAWGTree(stage string) error {
	source := filepath.Join(e.dir, awgTreeName)
	target := filepath.Join(stage, awgTreeName)
	if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrUnavailable
	}
	if err := validateAWGTree(source); err != nil {
		return err
	}
	return copyAWGTree(source, target)
}

// validateAWGTree accepts only bounded root-private connector directories with valid normalized profiles and metadata.
func validateAWGTree(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		return ErrUnavailable
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) > 64 {
		return ErrUnavailable
	}
	var total int64
	for _, entry := range entries {
		id := entry.Name()
		if !awgID(id) || !entry.IsDir() {
			return ErrUnavailable
		}
		connectorPath := filepath.Join(path, id)
		if _, _, err := readAWGDirectory(connectorPath, id, &total); err != nil {
			return err
		}
	}
	if total > 2<<20 {
		return ErrUnavailable
	}
	return nil
}

// readAWGDirectory returns validated metadata and the normalized secret after checking one connector's exact root-only file set, metadata identity, and normalized profile.
func readAWGDirectory(path, id string, total *int64) (awg.Metadata, awg.Profile, error) {
	info, err := os.Lstat(path)
	stat, ok := infoStat(info)
	if err != nil || info == nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 2 {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	allowed := map[string]bool{"profile.conf": false, "metadata.json": false}
	for _, entry := range entries {
		if _, exists := allowed[entry.Name()]; !exists || entry.IsDir() {
			return awg.Metadata{}, awg.Profile{}, ErrUnavailable
		}
		allowed[entry.Name()] = true
		fileInfo, err := os.Lstat(filepath.Join(path, entry.Name()))
		fileStat, ok := infoStat(fileInfo)
		if err != nil || fileInfo == nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 || !ok || int(fileStat.Uid) != os.Geteuid() || int(fileStat.Gid) != os.Getegid() || fileStat.Nlink != 1 {
			return awg.Metadata{}, awg.Profile{}, ErrUnavailable
		}
		*total += fileInfo.Size()
		if *total > 2<<20 {
			return awg.Metadata{}, awg.Profile{}, ErrUnavailable
		}
	}
	for _, present := range allowed {
		if !present {
			return awg.Metadata{}, awg.Profile{}, ErrUnavailable
		}
	}
	metadataBytes, err := os.ReadFile(filepath.Join(path, "metadata.json"))
	if err != nil || len(metadataBytes) > 8192 {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	var metadata awgStoredMetadata
	decoder := json.NewDecoder(bytes.NewReader(metadataBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&metadata) != nil || decoder.Decode(new(any)) != io.EOF || metadata.ID != id || !awg.ValidUnderlays(id, metadata.Underlays) || !awgID(metadata.Group) || metadata.Priority < 1 || metadata.Slot < 0 || metadata.Slot >= awg.SlotCount || (metadata.Status != "configured" && metadata.Status != "ready") || (metadata.Protocol != "wireguard" && metadata.Protocol != "amneziawg") {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	profileBytes, err := os.ReadFile(filepath.Join(path, "profile.conf"))
	if err != nil || len(profileBytes) > 32<<10 {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	profile, err := awg.Parse(profileBytes)
	if err != nil || profile.IPv6Blocked != metadata.IPv6Blocked || profile.Protocol != metadata.Protocol || profile.IPv4Address != metadata.IPv4Address || profile.DNSIPv4 != metadata.DNSIPv4 {
		return awg.Metadata{}, awg.Profile{}, ErrUnavailable
	}
	return metadata, profile, nil
}

// awgID accepts a bounded lowercase identifier without exposing profile data in filesystem errors.
func awgID(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, char := range value[1:] {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}
	return true
}

// copyAWGTree copies only validated regular connector files and preserves their root-private modes.
func copyAWGTree(source, destination string) error {
	if err := validateAWGTree(source); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return ErrUnavailable
	}
	for _, entry := range entries {
		target := filepath.Join(destination, entry.Name())
		if err := os.Mkdir(target, 0700); err != nil {
			return err
		}
		for _, name := range []string{"profile.conf", "metadata.json"} {
			if err := copyPrivateAWGFile(filepath.Join(source, entry.Name(), name), filepath.Join(target, name)); err != nil {
				return err
			}
		}
		if err := syncDir(target); err != nil {
			return err
		}
	}
	if err := syncDir(destination); err != nil {
		return err
	}
	return validateAWGTree(destination)
}

// copyAWGTreeIfPresent copies a validated AWG tree or preserves its absence as an empty generation artifact.
func copyAWGTreeIfPresent(source, destination string) error {
	if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrUnavailable
	}
	return copyAWGTree(source, destination)
}

// installAWGTree atomically replaces or removes the active secret tree while retaining an immediate local rollback path.
func (e Engine) installAWGTree(source string) error {
	if err := verifyAWGTreeDigest(filepath.Dir(source)); err != nil {
		return err
	}
	active := filepath.Join(e.dir, awgTreeName)
	stage, err := os.MkdirTemp(e.dir, ".binding-awg-install-")
	if err != nil {
		return err
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := copyAWGTreeIfPresent(source, stage); err != nil {
		return err
	}
	backup, err := os.MkdirTemp(e.dir, ".binding-awg-backup-")
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	defer os.RemoveAll(backup)
	if _, err := os.Lstat(active); err == nil {
		if err := os.Rename(active, backup); err != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	if _, err := os.Lstat(source); err == nil {
		if err := os.Rename(stage, active); err != nil {
			if _, backupErr := os.Lstat(backup); backupErr == nil {
				_ = os.Rename(backup, active)
			}
			return ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		if _, backupErr := os.Lstat(backup); backupErr == nil {
			_ = os.Rename(backup, active)
		}
		return ErrUnavailable
	}
	if err := syncDir(e.dir); err != nil {
		if _, activeErr := os.Lstat(active); activeErr == nil {
			_ = os.RemoveAll(active)
		}
		if _, backupErr := os.Lstat(backup); backupErr == nil {
			_ = os.Rename(backup, active)
		}
		return ErrUnavailable
	}
	return os.RemoveAll(backup)
}

// copyPrivateAWGFile copies one already validated private regular file using exclusive creation and fsync.
func copyPrivateAWGFile(source, destination string) error {
	info, err := os.Lstat(source)
	stat, ok := infoStat(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() || stat.Nlink != 1 {
		return ErrUnavailable
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return ErrUnavailable
	}
	return writeDurably(destination, data)
}

// awgTreeDigest hashes a sorted, validated path-and-content manifest for the secret connector tree.
func awgTreeDigest(path string) ([]byte, error) {
	if err := validateAWGTree(path); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	hash := sha256.New()
	var names []string
	for _, entry := range entries {
		for _, name := range []string{"metadata.json", "profile.conf"} {
			names = append(names, filepath.Join(entry.Name(), name))
		}
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(path, name))
		if err != nil {
			return nil, ErrUnavailable
		}
		if _, err := fmt.Fprintf(hash, "%s\x00%d\x00", name, len(data)); err != nil {
			return nil, err
		}
		if _, err := hash.Write(data); err != nil {
			return nil, err
		}
	}
	return []byte(hex.EncodeToString(hash.Sum(nil)) + "\n"), nil
}

// verifyAWGTreeDigest rejects altered connector files before they enter a journaled installation.
func verifyAWGTreeDigest(directory string) error {
	path := filepath.Join(directory, "awg.sha256")
	saved, err := os.ReadFile(path)
	if err != nil || len(saved) != sha256.Size*2+1 || strings.TrimSpace(string(saved)) == "" {
		return ErrUnavailable
	}
	tree, err := awgTreeDigest(filepath.Join(directory, awgTreeName))
	if err != nil || !bytes.Equal(saved, tree) {
		return ErrUnavailable
	}
	return nil
}

// infoStat returns trusted Unix ownership metadata when available without dereferencing filesystem links.
func infoStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}
