package awg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestRouteManifestPublicationIgnoresCrashLeftover verifies stale fixed temp files cannot wedge publication.
func TestRouteManifestPublicationIgnoresCrashLeftover(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "routes.json")
	leftover := filepath.Join(directory, "routes.json.next")
	if err := os.WriteFile(leftover, []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	want := routeManifest{ID: "awg-test", Mark: "0x202", Table: "202", Priority: "1002", Device: "awg0"}
	if err := writeRouteManifest(path, want); err != nil {
		t.Fatalf("first writeRouteManifest returned error: %v", err)
	}
	if err := writeRouteManifest(path, want); err != nil {
		t.Fatalf("second writeRouteManifest returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("route manifest mode = %04o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got routeManifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("published route manifest is invalid JSON: %v", err)
	}
	if got != want {
		t.Fatalf("published route manifest = %#v, want %#v", got, want)
	}
	if data, err := os.ReadFile(leftover); err != nil || string(data) != "incomplete" {
		t.Fatalf("stale fixed temporary was changed: data=%q err=%v", data, err)
	}
}
