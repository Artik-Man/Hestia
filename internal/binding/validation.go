package binding

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Artik-Man/Hestia/internal/controller"
)

// privateDirectory checks a transaction directory with lstat so a symlink cannot redirect file reads.
func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != os.ModeDir|0700 || (int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() || int(info.Sys().(*syscall.Stat_t).Gid) != os.Getegid()) {
		return ErrUnavailable
	}
	return nil
}

// managedInfo accepts only a regular file owned by the helper with exactly the installed mode and group.
// Candidate files are staged privately. Installed snapshots alone grant read access to the installer's snapshot group.
func (e Engine) managedInfo(dir, name string, installed bool) (os.FileInfo, error) {
	mode, gid := os.FileMode(0600), os.Getegid()
	if installed && name == "snapshot.json" {
		mode, gid = 0640, e.snapshotGID
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil || info.Mode() != mode {
		return nil, ErrUnavailable
	}
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != gid || stat.Nlink != 1 {
		return nil, ErrUnavailable
	}
	return info, nil
}

// validateGeneration checks all managed files before the first privileged replacement.
// A damaged payload or digest leaves the entire generation untouched.
func (e Engine) validateGeneration(dir string, installed bool) error {
	for _, name := range managedFiles {
		if _, err := e.managedInfo(dir, name, installed); err != nil {
			return err
		}
	}
	for _, pair := range [][2]string{{"profile.json", "profile-source.sha256"}, {"sing-box.json", "profile-backend.sha256"}} {
		data, err := os.ReadFile(filepath.Join(dir, pair[0]))
		if err != nil {
			return err
		}
		digest, err := os.ReadFile(filepath.Join(dir, pair[1]))
		if err != nil || string(digest) != fmt.Sprintf("%x\n", sha256.Sum256(data)) {
			return ErrUnavailable
		}
	}
	snap, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return err
	}
	if _, err := controller.CheckSnapshot(snap); err != nil {
		return ErrUnavailable
	}
	return nil
}

// snapshotDigest computes the checksum of the exact snapshot bytes saved in one transaction generation.
func snapshotDigest(dir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("%x\n", sha256.Sum256(data))), nil
}

// verifySnapshotDigest rejects partial or modified snapshots even if the JSON is still a valid configuration.
func (e Engine) verifySnapshotDigest(dir string) error {
	if _, err := e.managedInfo(dir, "snapshot.sha256", false); err != nil {
		return err
	}
	saved, err := os.ReadFile(filepath.Join(dir, "snapshot.sha256"))
	if err != nil {
		return err
	}
	actual, err := snapshotDigest(dir)
	if err != nil || !bytes.Equal(saved, actual) {
		return ErrUnavailable
	}
	return nil
}
