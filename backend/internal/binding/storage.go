package binding

import (
	"bytes"
	"errors"

	"os"
	"path/filepath"

	"github.com/Artik-Man/Hestia/internal/storage"
)

// acquire obtains the existing installer lock without waiting; shared readers never create the lock.
// Its group-readable permissions are managed by the installer and systemd-tmpfiles.
func (e Engine) acquire(exclusive bool) (*os.File, error) {
	how := storage.LockShared
	if exclusive {
		how = storage.LockExclusive
	}
	lock, err := storage.OpenFile(e.lock, storage.ReadOnly|storage.NoFollow, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := storage.Flock(lock, how|storage.LockNonblock); err != nil {
		lock.Close()
		if storage.IsWouldBlock(err) {
			return nil, ErrConflict
		}
		return nil, ErrUnavailable
	}
	return lock, nil
}

// ReadSnapshot returns only a committed managed snapshot, refusing reads during an update or pending recovery.
func ReadSnapshot() ([]byte, error) { return Installed().readSnapshot() }

// readSnapshot checks the journal and reads the snapshot under the same shared lock as installation export.
func (e Engine) readSnapshot() ([]byte, error) {
	lock, err := e.acquire(false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	return os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
}

// validateInstallation requires a protected operator-owned directory and a regular installer marker before any mutations.
func (e Engine) validateInstallation() error {
	for _, name := range []string{e.dir, filepath.Join(e.dir, ".installer-managed")} {
		info, err := os.Lstat(name)
		if err != nil || int(storage.MustStat(info).Uid) != os.Geteuid() || info.Mode().Perm()&0022 != 0 {
			return ErrUnavailable
		}
		if name == e.dir && !info.IsDir() || name != e.dir && !info.Mode().IsRegular() {
			return ErrUnavailable
		}
	}
	marker, err := os.ReadFile(filepath.Join(e.dir, ".installer-managed"))
	if err != nil || string(marker) != "1\n" {
		return ErrUnavailable
	}
	return nil
}

// syncDir flushes directory entries after publishing or retiring a journal or replacing installed files.
func syncDir(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// copyConfig atomically installs a regular file with the original owner's permissions and flushes its contents.
func copyConfig(src, dest string, info os.FileInfo) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(dest), ".binding-file-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	owner := storage.MustStat(info)
	if err := temp.Chown(int(owner.Uid), int(owner.Gid)); err != nil {
		return err
	}
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), dest)
}

// publishJournal backs up all installed files before exposing a durable recovery generation.
// Earlier staging failures leave the active configuration untouched.
func (e Engine) publishJournal(stage string) error {
	previous := filepath.Join(stage, "previous")
	if err := os.Mkdir(previous, 0700); err != nil {
		return err
	}
	if err := privateDirectory(stage); err != nil {
		return err
	}
	if err := e.validateGeneration(e.dir, true); err != nil {
		return err
	}
	if err := e.validateGeneration(stage, false); err != nil {
		return err
	}
	for _, name := range managedFiles {
		path := filepath.Join(e.dir, name)
		info, err := e.managedInfo(e.dir, name, true)
		if err != nil {
			return err
		}
		if err := copyConfig(path, filepath.Join(previous, name), info); err != nil {
			return err
		}
	}
	if err := copyAWGTreeIfPresent(filepath.Join(e.dir, awgTreeName), filepath.Join(previous, awgTreeName)); err != nil {
		return err
	}
	for _, dir := range []string{stage, previous} {
		digest, err := snapshotDigest(dir)
		if err != nil {
			return err
		}
		if err := writeDurably(filepath.Join(dir, "snapshot.sha256"), digest); err != nil {
			return err
		}
		awgDigest, err := awgTreeDigest(filepath.Join(dir, awgTreeName))
		if err != nil {
			return err
		}
		if err := writeDurably(filepath.Join(dir, "awg.sha256"), awgDigest); err != nil {
			return err
		}
	}
	if err := syncDir(previous); err != nil {
		return err
	}
	if err := syncDir(stage); err != nil {
		return err
	}
	if err := os.Rename(stage, filepath.Join(e.dir, pending)); err != nil {
		return err
	}
	return syncDir(e.dir)
}

const routingOnlyMarker = "routing-only"

// routingOnly reads the private journal marker for operations that preserve the connector runtime.
// Its absence selects full recovery, including journals published before this marker existed.
func (e Engine) routingOnly(journal string) (bool, error) {
	if err := privateDirectory(journal); err != nil {
		return false, err
	}
	path := filepath.Join(journal, routingOnlyMarker)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if _, err := e.managedInfo(journal, routingOnlyMarker, false); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "1\n" {
		return false, ErrUnavailable
	}
	return true, nil
}

// installFiles replaces managed files using the metadata preserved in the transaction backup.
// A failure leaves the journal intact so the full previous generation can be restored idempotently.
func (e Engine) installFiles(from string, routingOnly bool) error {
	journal := filepath.Join(e.dir, pending)
	previous := filepath.Join(journal, "previous")
	for _, dir := range []string{journal, previous} {
		if err := privateDirectory(dir); err != nil {
			return err
		}
	}
	if err := e.validateGeneration(previous, true); err != nil {
		return err
	}
	if err := e.verifySnapshotDigest(previous); err != nil {
		return err
	}
	if from != previous {
		if err := e.verifySnapshotDigest(from); err != nil {
			return err
		}
		if err := e.validateGeneration(from, false); err != nil {
			return err
		}
	}
	if err := verifyAWGTreeDigest(from); err != nil {
		return err
	}
	if routingOnly {
		current, err := awgTreeDigest(filepath.Join(e.dir, awgTreeName))
		if err != nil {
			return err
		}
		expected, err := os.ReadFile(filepath.Join(from, "awg.sha256"))
		if err != nil || !bytes.Equal(current, expected) {
			return ErrUnavailable
		}
	}
	for _, name := range managedFiles {
		info, err := e.managedInfo(previous, name, true)
		if err != nil {
			return err
		}
		if err := copyConfig(filepath.Join(from, name), filepath.Join(e.dir, name), info); err != nil {
			return err
		}
	}
	if !routingOnly {
		if err := e.installAWGTree(filepath.Join(from, awgTreeName)); err != nil {
			return err
		}
	}
	return syncDir(e.dir)
}

// retireJournal atomically removes the pending marker only after a successful commit or rollback.
// Backup cleanup follows the durable rename, so a partially removed backup is never used for recovery.
func (e Engine) retireJournal() error {
	garbage, err := os.MkdirTemp(e.dir, ".binding-finished-")
	if err != nil {
		return err
	}
	journal := filepath.Join(e.dir, pending)
	finished := filepath.Join(garbage, "generation")
	if err := os.Rename(journal, finished); err != nil {
		_ = os.Remove(garbage)
		return err
	}
	if err := syncDir(e.dir); err != nil {
		// Keep the backups until the removal of the marker is known to be durable.
		return errors.Join(err, os.Rename(finished, journal))
	}
	_ = os.RemoveAll(garbage)
	return nil
}

// writeDurably creates a private, exclusive transaction record and flushes its contents before publication.
func writeDurably(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
