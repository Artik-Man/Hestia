//go:build linux && keenetic

package keeneticroute

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestOwnedIngressRuleRegistryPersistsOnlyPrivateIdentities checks durable rule ownership and strict file metadata.
func TestOwnedIngressRuleRegistryPersistsOnlyPrivateIdentities(t *testing.T) {
	directory := privateIngressStateTestDirectory(t)
	path := filepath.Join(directory, "rules.json")
	rule := ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Table: 30001, Action: ingressRuleLookup, Input: "br0", HasMark: true}
	if _, err := readOwnedIngressRules(path); err != nil {
		t.Fatal(err)
	}
	rule.Owned = true
	if err := writeOwnedIngressRules(path, []ingressRule{rule}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("Owned")) {
		t.Fatalf("runtime ownership flag was persisted: %s", data)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("registry file mode is not private: info=%v err=%v", info, err)
	}
	loaded, err := readOwnedIngressRules(path)
	if err != nil || len(loaded) != 1 || loaded[0].Owned || !sameIngressRuleIdentity(loaded[0], rule) {
		t.Fatalf("registry identity was not loaded safely: rules=%#v err=%v", loaded, err)
	}
}

// TestReconcileOwnedIngressRulesPrunesAbsentRules prevents stale state from adopting a later foreign exact match.
func TestReconcileOwnedIngressRulesPrunesAbsentRules(t *testing.T) {
	path := filepath.Join(privateIngressStateTestDirectory(t), "rules.json")
	rule := ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Table: 30001, Action: ingressRuleLookup, Input: "br0", HasMark: true}
	if err := writeOwnedIngressRules(path, []ingressRule{rule}); err != nil {
		t.Fatal(err)
	}
	active, err := reconcileOwnedIngressRules(path, []ingressRule{rule})
	if err != nil || len(active) != 1 || !active[0].Owned {
		t.Fatalf("persisted identity was not marked as owned: rules=%#v err=%v", active, err)
	}
	if _, err := reconcileOwnedIngressRules(path, nil); err != nil {
		t.Fatal(err)
	}
	foreign, err := reconcileOwnedIngressRules(path, []ingressRule{rule})
	if err != nil || len(foreign) != 1 || foreign[0].Owned {
		t.Fatalf("stale registry identity adopted a later foreign rule: rules=%#v err=%v", foreign, err)
	}
}

// TestReadOwnedIngressRulesRejectsUnsafeFilesystemObjects refuses symlinks, hard links, and permissive state directories.
func TestReadOwnedIngressRulesRejectsUnsafeFilesystemObjects(t *testing.T) {
	t.Run("file symlink", func(t *testing.T) {
		directory := privateIngressStateTestDirectory(t)
		path := filepath.Join(directory, "rules.json")
		if err := os.Symlink(filepath.Join(directory, "missing"), path); err != nil {
			t.Fatal(err)
		}
		if _, err := readOwnedIngressRules(path); err == nil {
			t.Fatal("symlinked registry was accepted")
		}
	})
	t.Run("hard link", func(t *testing.T) {
		directory := privateIngressStateTestDirectory(t)
		path := filepath.Join(directory, "rules.json")
		if err := writeOwnedIngressRules(path, nil); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(path, filepath.Join(directory, "second-link")); err != nil {
			t.Fatal(err)
		}
		if _, err := readOwnedIngressRules(path); err == nil {
			t.Fatal("hard-linked registry was accepted")
		}
	})
	t.Run("permissive directory", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := readOwnedIngressRules(filepath.Join(directory, "rules.json")); err == nil {
			t.Fatal("permissive registry directory was accepted")
		}
	})
}

// privateIngressStateTestDirectory gives filesystem tests the same owner-only permissions as the Keenetic runtime directory.
func privateIngressStateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatalf("cannot secure test state directory: %v", err)
	}
	return directory
}
