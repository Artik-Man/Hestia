package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/quality"
)

// TestRouteOverridesStayOnPhysicalExits verifies that a direct resolver cannot replace a tunnel's resolver or attach to an unknown exit.
func TestRouteOverridesStayOnPhysicalExits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paths.json")
	original := installedRoutes{Inode: 1, Modified: 10, Paths: []quality.Path{{ID: "cable", Device: "eth0"}, {ID: "fixture-wg", SocksAddress: "127.0.0.1:27001", SocksPassword: "local-fixture-only"}, {ID: "fixture-awg", Device: "awg0", Mark: 514}}, Resolvers: map[string]string{"fixture-wg": "192.0.2.53", "fixture-awg": "192.0.2.54"}}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	allowed, err := loadRoutes(path, map[string]string{"cable": "198.51.100.53"})
	if err != nil || allowed.Resolvers["cable"] != "198.51.100.53" || allowed.Resolvers["fixture-wg"] != "192.0.2.53" || allowed.Resolvers["fixture-awg"] != "192.0.2.54" {
		t.Fatalf("unexpected valid path configuration: err=%v", err)
	}
	for _, overrides := range []map[string]string{{"fixture-wg": "198.51.100.53"}, {"fixture-awg": "198.51.100.53"}, {"unknown": "198.51.100.53"}, {"cable": "127.0.0.1"}, {"cable": "dns.example"}} {
		if _, err := loadRoutes(path, overrides); err == nil {
			t.Fatalf("unsafe DNS override accepted: %v", overrides)
		}
	}
}

// TestDNSGenerationRecovery checks that an atomic live replacement withdraws stale transports
// and requests a supervisor restart, while a subsequent fresh export remains active.
func TestDNSGenerationRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, []byte("one"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := func() *installedRoutes {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return &installedRoutes{Inode: info.Sys().(*syscall.Stat_t).Ino, Modified: info.ModTime().UnixNano()}
	}
	first := stamp()
	if !first.currentGeneration(path) {
		t.Fatal("new export rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- watchGeneration(ctx, first, path, time.Millisecond) }()
	if err := os.WriteFile(path+".next", []byte("two"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".next", path); err != nil {
		t.Fatal(err)
	}
	if first.currentGeneration(path) {
		t.Fatal("outdated export accepted")
	}
	if err := <-result; !errors.Is(err, errRouteGeneration) {
		t.Fatalf("expected a fresh privileged export: %v", err)
	}
	second := stamp()
	if !second.currentGeneration(path) {
		t.Fatal("replacement export rejected")
	}
	cancel()
	if err := watchGeneration(ctx, second, path, time.Second); err != nil {
		t.Fatalf("normal shutdown requested a restart: %v", err)
	}
}

// TestDNSRevocationDuringDial checks that fresh authorization permits writes and revoked authorization closes without sending a DNS query.
func TestDNSRevocationDuringDial(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		for _, revoke := range []bool{false, true} {
			name := "allowed"
			if revoke {
				name = "withdrawn"
			}
			t.Run(network+"/"+name, func(t *testing.T) {
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				allowed := true
				path := quality.Path{DialContext: func(_ context.Context, n, target string) (net.Conn, error) {
					if n != network || target != "192.0.2.53:53" {
						t.Fatalf("unexpected dial %s %s", n, target)
					}
					allowed = !revoke
					return client, nil
				}}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				conn, err := dialAuthorized(ctx, path, network, "192.0.2.53:53", func(context.Context) bool { return allowed })
				if revoke {
					if err == nil || conn != nil {
						t.Fatal("withdrawn route retained a writable socket")
					}
					var b [1]byte
					if n, err := server.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
						t.Fatalf("expected closed socket without a query, got %d %v", n, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				done := make(chan error, 1)
				go func() { _, err := conn.Write([]byte("question")); done <- err }()
				var b [8]byte
				if _, err := io.ReadFull(server, b[:]); err != nil || string(b[:]) != "question" {
					t.Fatalf("authorized transport: %v", err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
