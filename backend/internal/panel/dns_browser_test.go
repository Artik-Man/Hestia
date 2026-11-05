package panel

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestDNSPanelPlaywright serves the built Angular app and the real policy API to an isolated browser.
// The frontend browser suite enables this test after building assets and installing Chromium.
func TestDNSPanelPlaywright(t *testing.T) {
	if os.Getenv("HESTIA_DNS_BROWSER_TEST") != "1" {
		t.Skip("run npm run test:browser:dns-api from frontend")
	}
	runDNSBrowser(t, t.TempDir(), "dns-persistence.mjs")
}

// TestDNSPanelWarmFixture serves the worker integration harness's temporary policy and heartbeat to Chromium.
func TestDNSPanelWarmFixture(t *testing.T) {
	dir := os.Getenv("HESTIA_DNS_WARM_FIXTURE_DIR")
	if dir == "" || os.Getenv("HESTIA_DNS_BROWSER_TEST") != "1" {
		t.Skip("started by TestDNSWorkerPlaywright")
	}
	runDNSBrowser(t, dir, "dns-worker.mjs")
}

// runDNSBrowser exposes only a loopback Go panel and invokes the named browser case with bounded lifetime.
func runDNSBrowser(t *testing.T, dir, script string) {
	t.Helper()
	frontend, err := filepath.Abs("../../../frontend")
	if err != nil {
		t.Fatal(err)
	}
	assets, err := readAssets(filepath.Join(frontend, "dist/hestia/browser"))
	if err != nil {
		t.Fatal(err)
	}
	writes := panelWrites{dnsPolicyPath: filepath.Join(dir, "policy.json"), dnsReportPath: filepath.Join(dir, "report.json")}
	handler, err := localHandler("127.0.0.1:0", panelHandler("../../../deploy/bootstrap/snapshot.json", "", assets, writes))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	browser := exec.CommandContext(ctx, "node", "--test", filepath.Join("tests", "browser", script))
	browser.WaitDelay = 3 * time.Second
	browser.Dir = frontend
	browser.Env = append(os.Environ(), "HESTIA_DNS_BROWSER_FIXTURE="+server.URL)
	output, err := browser.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
}
