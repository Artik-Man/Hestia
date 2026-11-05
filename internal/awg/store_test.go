package awg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
