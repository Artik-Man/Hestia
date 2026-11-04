//go:build linux

package observer

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestCancelStalledEcho requires bounded shutdown even when a connected peer holds the request without replying.
func TestCancelStalledEcho(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			target := Target{Address: "127.0.0.1", Protocol: protocol}
			received := make(chan struct{})
			switch protocol {
			case "tcp":
				listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				target.Port = listener.Addr().(*net.TCPAddr).Port
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					defer conn.Close()
					buf := make([]byte, 39)
					if _, err := io.ReadFull(conn, buf); err == nil {
						close(received)
					}
					io.Copy(io.Discard, conn)
				}()
			case "udp":
				listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				target.Port = listener.LocalAddr().(*net.UDPAddr).Port
				go func() {
					if _, _, err := listener.ReadFrom(make([]byte, 256)); err == nil {
						close(received)
					}
				}()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			response := make(chan Probe, 1)
			go func() { response <- measure(ctx, Connection{ID: "loop", Interface: "lo"}, target, time.Minute) }()
			select {
			case <-received:
			case p := <-response:
				t.Fatalf("could not bind/send loopback probe: %+v", p)
			case <-time.After(time.Second):
				t.Fatal("no probe at test listener")
			}
			cancel()
			select {
			case <-response:
			case <-time.After(time.Second):
				t.Fatal("probe waited for its minute-long timeout after cancellation")
			}
		})
	}
}

// TestSilentUDPPeerCountsAsLoss distinguishes a sent datagram with no echo from a local socket failure.
func TestSilentUDPPeerCountsAsLoss(t *testing.T) {
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	target := Target{Address: "127.0.0.1", Port: peer.LocalAddr().(*net.UDPAddr).Port, Protocol: "udp"}
	for i := 0; i < 10; i++ {
		got := measure(context.Background(), Connection{Interface: "lo"}, target, 20*time.Millisecond)
		if got.Status != Lost {
			t.Fatalf("silent peer reported as %+v", got)
		}
	}
}
