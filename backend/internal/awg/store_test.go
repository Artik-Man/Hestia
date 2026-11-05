package awg

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestStoreSaveLoadListAndDelete verifies persistence permissions, metadata redaction, and replacement semantics.
func TestStoreSaveLoadListAndDelete(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	metadata := Metadata{ID: "awg-test", Group: "fi", Priority: 2}
	if err := store.Save(metadata, []byte(validProfile)); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 || !reflect.DeepEqual(entries[0], Metadata{ID: "awg-test", Group: "fi", Priority: 2, Status: "configured", Protocol: "amneziawg", IPv4Address: "10.66.66.2/32", DNSIPv4: "1.1.1.1"}) {
		t.Fatalf("unexpected listed metadata: %#v, %v", entries, err)
	}
	loaded, config, err := store.Load("awg-test")
	if err != nil || !reflect.DeepEqual(loaded, entries[0]) || !strings.Contains(string(config), "PrivateKey =") {
		t.Fatalf("unexpected stored profile: %#v, %v", loaded, err)
	}
	profileInfo, err := os.Stat(filepath.Join(store.directory, "awg-test", profileFile))
	if err != nil || profileInfo.Mode().Perm() != 0600 {
		t.Fatalf("secret profile permissions are not 0600: %v, %v", profileInfo, err)
	}
	metadataBytes, err := os.ReadFile(filepath.Join(store.directory, "awg-test", metadataFile))
	if err != nil || strings.Contains(string(metadataBytes), "PrivateKey") || strings.Contains(string(metadataBytes), "AAAAAAAA") {
		t.Fatalf("public metadata contains private material: %s", metadataBytes)
	}
	metadata.Group, metadata.Priority = "ru", 1
	if err := store.Save(metadata, []byte(validProfile)); err != nil {
		t.Fatalf("Save update returned error: %v", err)
	}
	loaded, _, err = store.Load("awg-test")
	if err != nil || loaded.Group != "ru" || loaded.Priority != 1 {
		t.Fatalf("updated metadata was not published: %#v, %v", loaded, err)
	}
	if err := store.Delete("awg-test"); err != nil {
		t.Fatalf("Delete returned error: %v", err)
	}
	entries, err = store.List()
	if err != nil || len(entries) != 0 {
		t.Fatalf("deleted connection is still listed: %#v, %v", entries, err)
	}
}

// TestStoreRecoversInterruptedReplacement restores the previous record when publication stopped before the new directory appeared.
func TestStoreRecoversInterruptedReplacement(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	metadata := Metadata{ID: "awg-test", Group: "fi", Priority: 1}
	if err := store.Save(metadata, []byte(validProfile)); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	if err := os.Rename(filepath.Join(store.directory, metadata.ID), store.backupPath(metadata.ID)); err != nil {
		t.Fatalf("prepare interrupted swap: %v", err)
	}
	store, err = OpenStore(store.directory)
	if err != nil {
		t.Fatalf("OpenStore recovery returned error: %v", err)
	}
	loaded, _, err := store.Load(metadata.ID)
	if err != nil || loaded.ID != metadata.ID {
		t.Fatalf("interrupted replacement was not restored: %#v, %v", loaded, err)
	}
}

// TestStoreRejectsUnsafeIdentityAndPermissions ensures invalid paths and permissive files are refused.
func TestStoreRejectsUnsafeIdentityAndPermissions(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatalf("OpenStore returned error: %v", err)
	}
	if err := store.Save(Metadata{ID: "../escape", Group: "fi", Priority: 1}, []byte(validProfile)); err == nil {
		t.Fatal("Save accepted a path-like ID")
	}
	if err := store.Save(Metadata{ID: "awg-test", Group: "fi", Priority: 1}, []byte(validProfile)); err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	path := filepath.Join(store.directory, "awg-test", profileFile)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("Chmod returned error: %v", err)
	}
	if _, _, err := store.Load("awg-test"); err == nil {
		t.Fatal("Load accepted a group-readable secret file")
	}
}

// TestProfileListingAlongsideCatalog verifies repeated helper-style opens and lists finish while a catalog reader holds the installer lock.
func TestProfileListingAlongsideCatalog(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatal(err)
	}
	const id = "awg-test"
	if err := store.Save(Metadata{ID: id, Group: "fi", Priority: 1}, []byte(validProfile)); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(store.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		for range 3 {
			reopened, err := OpenStoreWithLock(store.directory, store.lockPath)
			if err != nil {
				done <- err
				return
			}
			rows, err := reopened.List()
			if err != nil {
				done <- err
				return
			}
			if len(rows) != 1 || rows[0].ID != id {
				done <- fmt.Errorf("unexpected public metadata: %+v", rows)
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_UN); err != nil {
			t.Fatal(err)
		}
		<-done
		t.Fatal("listing public profiles waited for a concurrent catalog reader")
	}
}

// TestListRecoversAfterCatalogReaderLeaves checks that an interrupted replacement is restored before returning metadata, with exclusive access.
func TestListRecoversAfterCatalogReaderLeaves(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "awg"))
	if err != nil {
		t.Fatal(err)
	}
	const id = "awg-test"
	if err := store.Save(Metadata{ID: id, Group: "fi", Priority: 1}, []byte(validProfile)); err != nil {
		t.Fatal(err)
	}
	backup := store.backupPath(id)
	if err := os.Rename(filepath.Join(store.directory, id), backup); err != nil {
		t.Fatal(err)
	}

	reader, err := os.Open(store.lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		rows, err := store.List()
		if err == nil && (len(rows) != 1 || rows[0].ID != id) {
			err = fmt.Errorf("unexpected recovered metadata: %+v", rows)
		}
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("list completed before exclusive recovery was possible: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := os.Lstat(backup); err != nil {
		t.Fatalf("backup changed while shared reader held the lock: %v", err)
	}
	if err := syscall.Flock(int(reader.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not finish after the catalog reader left")
	}
	if _, err := os.Lstat(backup); !os.IsNotExist(err) {
		t.Fatalf("backup remains after recovery: %v", err)
	}
}
