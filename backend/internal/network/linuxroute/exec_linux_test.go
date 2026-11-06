package linuxroute

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestIPRouteMissingTable verifies only iproute2's exact absent-table response is usable as an empty dump.
func TestIPRouteMissingTable(t *testing.T) {
	dir := t.TempDir()
	program := filepath.Join(dir, "ip")
	script := `#!/bin/sh
cat "${0%/*}/stdout"
cat "${0%/*}/stderr" >&2
exit 2
`
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		family, verb, table, stderr, stdout string
		empty                               bool
	}{
		{"-4", "show", "202", "Error: ipv4: FIB table does not exist.\nDump terminated", "", true},
		{"-6", "show", "202", "Error: ipv6: FIB table does not exist.\nDump terminated", "", true},
		{"-4", "show", "202", "Error: ipv6: FIB table does not exist.\nDump terminated", "", false},
		{"-4", "show", "202", "RTNETLINK answers: Operation not permitted", "", false},
		{"-4", "show", "202", "Error: ipv4: FIB table does not exist.\nDump terminated\nOther error", "", false},
		{"-4", "show", "202", "Error: ipv4: FIB table does not exist.\nDump terminated", "default dev eth0", false},
		{"-4", "del", "202", "Error: ipv4: FIB table does not exist.\nDump terminated", "", false},
		{"-4", "show", "254", "Error: ipv4: FIB table does not exist.\nDump terminated", "", false},
		{"-4", "show", "203", "Error: ipv4: FIB table does not exist.\nDump terminated", "", true},
	} {
		if err := os.WriteFile(filepath.Join(dir, "stderr"), []byte(tc.stderr+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stdout"), []byte(tc.stdout), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := runIPRoute(context.Background(), program, tc.family, "route", tc.verb, "table", tc.table)
		if (err == nil) != tc.empty || len(out) != 0 {
			t.Fatalf("%+v gave %q, %v", tc, out, err)
		}
	}
}
