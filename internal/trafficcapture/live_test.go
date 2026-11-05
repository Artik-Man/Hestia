package trafficcapture

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
)

// TestLocalSingBoxJournal exercises the real loopback SOCKS router, Clash WebSocket and persistent journal when the pinned binary is supplied.
func TestLocalSingBoxJournal(t *testing.T) {
	binary := os.Getenv("HESTIA_TEST_SING_BOX")
	if binary == "" {
		t.Skip("set HESTIA_TEST_SING_BOX to a local sing-box 1.14.4 binary")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	const body = "journal-smoke"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
	defer target.Close()

	socks, clash := localPort(t), localPort(t)
	if socks == clash {
		t.Fatal("ephemeral ports collided")
	}
	cfg := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:%d"}},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":%d}],"outbounds":[{"type":"selector","tag":"home","outbounds":["direct"]},{"type":"direct","tag":"direct"},{"type":"block","tag":"off"}],"route":{"final":"home","rules":[{"ip_cidr":"127.0.0.2/32","action":"reject"},{"ip_cidr":"127.0.0.3/32","action":"route","outbound":"off"},{"ip_cidr":"127.0.0.1/32","action":"route","outbound":"home"}]}}`, clash, socks)
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, binary, "run", "-c", path)
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	store, err := traffic.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		run(ctx, fmt.Sprintf("ws://127.0.0.1:%d/logs?level=debug", clash), store)
	}()
	defer func() { cancel(); <-finished }()
	wait := func(count int) traffic.TrafficPage {
		t.Helper()
		for {
			page, err := store.Page(ctx, traffic.Query{Limit: 10})
			if err != nil {
				t.Fatal(err)
			}
			if page.SourceAvailable && page.Total >= count {
				return page
			}
			select {
			case <-ctx.Done():
				t.Fatal("timed out waiting for live journal")
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	wait(0)
	via, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", socks))
	client := http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(via), DisableKeepAlives: true}, Timeout: 2 * time.Second}
	defer client.CloseIdleConnections()
	for i, host := range []string{"127.0.0.1", "localhost", "127.0.0.2", "127.0.0.3"} {
		res, err := client.Get(strings.Replace(target.URL, "127.0.0.1", host, 1))
		if err != nil {
			if i < 2 {
				t.Fatal(err)
			}
			continue
		}
		b, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if i >= 2 || err != nil || string(b) != body {
			t.Fatalf("unexpected response to %s", host)
		}
	}
	page := wait(4)
	if page.Total != 4 || page.Lost != 0 {
		t.Fatalf("total=%d lost=%d", page.Total, page.Lost)
	}
	for _, e := range page.Events {
		if e.Protocol != "TCP" || e.Port == 0 {
			t.Fatalf("invalid TCP observation: %+v", e)
		}
		switch {
		case e.Address == "127.0.0.2" || e.Address == "127.0.0.3":
			if e.Kind != traffic.Blocked || e.Connection != "" || e.BlockReason == "" {
				t.Fatalf("incorrect denial: %+v", e)
			}
		case e.Address == "127.0.0.1":
			if e.Group != "home" || e.Connection != "direct" || e.Kind != traffic.Unconfirmed {
				t.Fatalf("incorrect route: %+v", e)
			}
		case e.Domain == "localhost":
			if e.Connection != "direct" || e.Address != "" {
				t.Fatalf("invented or missing domain evidence: %+v", e)
			}
		default:
			t.Fatalf("unexpected record: %+v", e)
		}
	}
}

// localPort selects a currently unused ephemeral loopback port for the isolated sing-box child.
func localPort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return netip.MustParseAddrPort(l.Addr().String()).Port()
}
