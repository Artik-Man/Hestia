package dnsresolver

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestUDPFixture verifies one real UDP resolver exchange exclusively on the loopback interface.
func TestUDPFixture(t *testing.T) {
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(2 * time.Second))
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := peer.ReadFrom(buf)
		if err == nil {
			var p []byte
			p, err = fixtureAnswer(buf[:n], dnsmessage.RCodeSuccess, 120, 8)
			if err == nil {
				_, err = peer.WriteTo(p, addr)
			}
		}
		result <- err
	}()
	routes := &testRoutes{allowed: []Upstream{{"fixture", peer.LocalAddr().String()}}}
	routes.send = func(ctx context.Context, up Upstream, p []byte) ([]byte, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp4", up.Resolver)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		deadline, _ := ctx.Deadline()
		conn.SetDeadline(deadline)
		if _, err = conn.Write(p); err != nil {
			return nil, err
		}
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		return buf[:n], err
	}
	r := New(testPolicy(t, nil), routes, "")
	m := testQuery(t, r, "loopback.example")
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatal(m)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
