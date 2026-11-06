package keeneticdiagnostics

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

// TestCLIRequiresInventory ensures help and invalid arguments never touch the inventory sources.
func TestCLIRequiresInventory(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"--version"}, {"--inventory", "extra"}, {"--unknown"}} {
		var out, errOut bytes.Buffer
		code := Run(args, &out, &errOut, nil, "linux", "arm64", "test")
		if len(args) > 0 && (args[0] == "--unknown" || len(args) > 1) {
			if code != 2 {
				t.Fatalf("args %v: status %d", args, code)
			}
		} else if code != 0 {
			t.Fatalf("args %v: status %d", args, code)
		}
	}
}

// TestInventoryMinimizesData confirms only allowed memory fields and capability uncertainty reach JSON.
func TestInventoryMinimizesData(t *testing.T) {
	sources := fstest.MapFS{
		"proc/sys/kernel/osrelease": {Data: []byte("5.10.0-test\n")},
		"proc/meminfo":              {Data: []byte("MemTotal: 524288 kB\nMemAvailable: 131072 kB\nSecretKey: DO-NOT-COPY\n")},
		"opt":                       {Mode: fs.ModeDir | 0755},
		"dev/net/tun":               {Mode: fs.ModeDevice | fs.ModeCharDevice | 0600},
		"opt/bin/ip":                {Mode: 0755},
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"--inventory"}, &out, &errOut, sources, "linux", "arm64", "test"); code != 0 {
		t.Fatalf("status %d: %s", code, errOut.String())
	}
	var report inventoryReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Kernel.Value != "5.10.0-test" || report.Memory.ValuesKiB["MemAvailable"] != 131072 {
		t.Fatalf("unexpected values: %+v", report)
	}
	if report.Paths["/dev/net/tun"].Kind != "character_device" || report.Utilities["ip"] != statusPresent {
		t.Fatalf("unexpected detection: %+v", report)
	}
	if strings.Contains(out.String(), "DO-NOT-COPY") {
		t.Fatal("unapproved field leaked")
	}
	for _, capability := range report.Capabilities {
		if capability != statusNotTested {
			t.Fatal("inventory asserts capability")
		}
	}
	if len(report.Capabilities) < 10 {
		t.Fatal("missing untested capabilities")
	}
}

// TestMissingAndUnreadableSources keeps absence distinct from a read or parse failure.
func TestMissingAndUnreadableSources(t *testing.T) {
	report := collectInventory(fstest.MapFS{}, "linux", "arm64", "test")
	if report.Kernel.Status != statusAbsent || report.Paths["/opt"].Status != statusAbsent {
		t.Fatalf("absence not reported: %+v", report)
	}
	report = collectInventory(fstest.MapFS{"proc/sys/kernel/osrelease": {Data: []byte("bad kernel value\n")}, "proc/meminfo": {Data: []byte("MemTotal: invalid kB\n")}}, "linux", "arm64", "test")
	if report.Kernel.Status != statusError || report.Memory.Status != statusError {
		t.Fatalf("malformed data accepted: %+v", report)
	}
	report = collectInventory(failingFS{}, "linux", "arm64", "test")
	if report.Kernel.Status != statusError || report.Utilities["ip"] != statusError {
		t.Fatalf("permission errors hidden: %+v", report)
	}
}

// failingFS simulates denied access without exposing underlying error strings in reports.
type failingFS struct{}

// Open denies every source read for error classification tests.
func (failingFS) Open(name string) (fs.File, error) { return nil, fs.ErrPermission }

// TestBoundedReads rejects oversized sources instead of retaining or publishing partial data.
func TestBoundedReads(t *testing.T) {
	sources := fstest.MapFS{"proc/sys/kernel/osrelease": {Data: []byte(strings.Repeat("a", 257))}, "proc/meminfo": {Data: []byte(strings.Repeat("a", 65537))}}
	report := collectInventory(sources, "linux", "arm64", "test")
	if report.Kernel.Status != statusError || report.Kernel.Value != "" || report.Memory.Status != statusError {
		t.Fatalf("oversized sources accepted: %+v", report)
	}
}

// TestUnsupportedOSDoesNotReadSources ensures a local macOS smoke run cannot impersonate Keenetic.
func TestUnsupportedOSDoesNotReadSources(t *testing.T) {
	report := collectInventory(nil, "darwin", "arm64", "test")
	if report.PlatformStatus != statusUnsupported || report.Kernel.Status != statusNotTested {
		t.Fatalf("unexpected unsupported result: %+v", report)
	}
}
