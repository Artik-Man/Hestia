package observer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScopedPublication starts with a live empty rule file and exercises multiple simultaneous UDP exceptions and recovery.
func TestScopedPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fi-udp.json")
	empty := []byte(`{"version":3,"rules":[]}`)
	if err := os.WriteFile(path, empty, 0644); err != nil {
		t.Fatal(err)
	}
	s := Settings{Group: "FI", Connections: []Connection{{ID: "FI1"}, {ID: "FI2"}}, Targets: []Target{{Address: "203.0.113.77", Protocol: "udp"}, {Address: "203.0.113.78", Protocol: "udp"}, {Address: "203.0.113.77", Protocol: "tcp"}}}
	rules, err := openExceptions(path, s)
	if err != nil {
		t.Fatal(err)
	}
	defer rules.close()
	if _, err := openExceptions(path, s); err == nil {
		t.Fatal("another writer acquired rules")
	}
	events := []struct{ proto, addr, to, reason, action, want string }{
		{"tcp", "203.0.113.77", "FI2", "better_delivery", "not_applicable", string(empty)},
		{"udp", "203.0.113.77", "FI2", "better_delivery", "added", `{"version":3,"rules":[{"ip_cidr":["203.0.113.77/32"]}]}`},
		{"udp", "203.0.113.78", "FI2", "better_delivery", "added", `{"version":3,"rules":[{"ip_cidr":["203.0.113.77/32"]},{"ip_cidr":["203.0.113.78/32"]}]}`},
		{"udp", "203.0.113.77", "FI1", "local_error", "unchanged", `{"version":3,"rules":[{"ip_cidr":["203.0.113.77/32"]},{"ip_cidr":["203.0.113.78/32"]}]}`},
		{"udp", "203.0.113.77", "FI1", "better_delivery", "removed", `{"version":3,"rules":[{"ip_cidr":["203.0.113.78/32"]}]}`},
	}
	for _, e := range events {
		got, err := rules.apply(Report{Group: "FI", Target: Target{Protocol: e.proto, Address: e.addr}, Recommended: e.to, Reason: e.reason})
		if got != e.action || err != nil {
			t.Fatalf("action %s: %v", got, err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != e.want {
			t.Fatalf("unexpected rules %s: %v", data, err)
		}
	}
	if err := os.WriteFile(path, empty, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.apply(Report{Group: "FI", Target: s.Targets[1], Recommended: "FI1", Reason: "better_delivery"}); err == nil {
		t.Fatal("overwrote external state")
	}
}

// TestColdStartRefusesForeignRules checks that a symlink and nonempty source data cannot be silently adopted.
func TestColdStartRefusesForeignRules(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "owned")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(file, []byte(`{"version":3,"rules":[{"ip_cidr":["0.0.0.0/0"]}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	s := Settings{Group: "FI", Connections: []Connection{{ID: "FI1"}, {ID: "FI2"}}, Targets: []Target{{Address: "203.0.113.77", Protocol: "udp"}}}
	for _, path := range []string{file, link} {
		if _, err := openExceptions(path, s); err == nil {
			t.Errorf("accepted %s", path)
		}
	}
}
