package binding

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const treeTestProfile = `[Interface]
Address = 10.66.66.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
DNS = 1.1.1.1

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
`

// TestAWGTreeCopyPreservesValidatedGeneration verifies private tree copies have identical content manifests.
func TestAWGTreeCopyPreservesValidatedGeneration(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "target")
	writeTestAWGTree(t, source)
	if err := validateAWGTree(source); err != nil {
		t.Fatalf("validateAWGTree rejected a valid tree: %v", err)
	}
	if err := copyAWGTree(source, target); err != nil {
		t.Fatalf("copyAWGTree failed: %v", err)
	}
	first, err := awgTreeDigest(source)
	if err != nil {
		t.Fatalf("awgTreeDigest(source) failed: %v", err)
	}
	second, err := awgTreeDigest(target)
	if err != nil || string(first) != string(second) {
		t.Fatalf("copied generation digest differs: %q, %q, %v", first, second, err)
	}
}

// TestAWGTreeRejectsUnexpectedAndLinkedEntries refuses special files and unexpected secret-tree paths.
func TestAWGTreeRejectsUnexpectedAndLinkedEntries(t *testing.T) {
	for _, name := range []string{"extra-file", "symlink"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "tree")
			writeTestAWGTree(t, root)
			if name == "extra-file" {
				if err := os.WriteFile(filepath.Join(root, "conn", "extra"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				profile := filepath.Join(root, "conn", "profile.conf")
				if err := os.Remove(profile); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/etc/passwd", profile); err != nil {
					t.Fatal(err)
				}
			}
			if err := validateAWGTree(root); err == nil {
				t.Fatal("accepted an unexpected or linked entry")
			}
		})
	}
}

// TestInstallAWGTreeReplacesOnlyTheValidatedGeneration verifies candidate tree replacement uses its recorded digest.
func TestInstallAWGTreeReplacesOnlyTheValidatedGeneration(t *testing.T) {
	root := t.TempDir()
	engine := Engine{dir: root}
	active := filepath.Join(root, awgTreeName)
	writeTestAWGTree(t, active)
	sourceDir := filepath.Join(root, "journal")
	source := filepath.Join(sourceDir, awgTreeName)
	if err := os.Mkdir(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestAWGTree(t, source)
	if err := os.WriteFile(filepath.Join(sourceDir, "awg.sha256"), mustAWGTreeDigest(t, source), 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.installAWGTree(source); err != nil {
		t.Fatalf("installAWGTree failed: %v", err)
	}
	if err := validateAWGTree(active); err != nil {
		t.Fatalf("installed AWG tree failed validation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "conn", "profile.conf"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := engine.installAWGTree(source); err == nil {
		t.Fatal("installed a tree whose journal digest no longer matches")
	}
}

// writeTestAWGTree creates one valid root-private connector fixture without real profile secrets.
func writeTestAWGTree(t *testing.T, root string) {
	t.Helper()
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	connector := filepath.Join(root, "conn")
	if err := os.Mkdir(connector, 0700); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(awgStoredMetadata{ID: "conn", Group: "group", Priority: 1, Status: "configured", Protocol: "wireguard", IPv4Address: "10.66.66.2/32", DNSIPv4: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"profile.conf": []byte(treeTestProfile), "metadata.json": metadata} {
		if err := os.WriteFile(filepath.Join(connector, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// mustAWGTreeDigest returns a valid fixture's journal digest or fails the current test.
func mustAWGTreeDigest(t *testing.T, path string) []byte {
	t.Helper()
	digest, err := awgTreeDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
