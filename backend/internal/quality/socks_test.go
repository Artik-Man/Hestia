package quality

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestAuthenticatedUDPRelay exercises the actual SOCKS UDP path while all test traffic stays on loopback.
func TestAuthenticatedUDPRelay(t *testing.T) {
	control, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err = udp.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveTestRelay(control, udp, deadline) }()
	path := Path{ID: "fi2", SocksAddress: control.Addr().String(), SocksPassword: "test-password"}
	conn, err := path.dial(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("dns")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || string(buf[:n]) != "good" {
		t.Fatalf("reply %q error %v", buf[:n], err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

// serveTestRelay verifies credentials and wire destination, then returns unrelated and matching datagrams.
func serveTestRelay(listener net.Listener, udp *net.UDPConn, deadline time.Time) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	if err = expectBytes(conn, []byte{5, 1, 2}); err != nil {
		return err
	}
	if _, err = conn.Write([]byte{5, 2}); err != nil {
		return err
	}
	if err = expectBytes(conn, []byte("\x01\x0ehestia-quality\x0dtest-password")); err != nil {
		return err
	}
	if _, err = conn.Write([]byte{1, 0}); err != nil {
		return err
	}
	if err = expectBytes(conn, []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	address := udp.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err = conn.Write(append([]byte{5, 0, 0}, socksEndpoint(address)...)); err != nil {
		return err
	}
	var buf [256]byte
	n, client, err := udp.ReadFromUDP(buf[:])
	if err != nil {
		return err
	}
	target := netip.MustParseAddrPort("1.1.1.1:53")
	header := append([]byte{0, 0, 0}, socksEndpoint(target)...)
	if string(buf[:n]) != string(header)+"dns" {
		return errors.New("unexpected datagram destination or body")
	}
	other := netip.MustParseAddrPort("8.8.8.8:53")
	bogus := append([]byte{0, 0, 0}, socksEndpoint(other)...)
	if _, err = udp.WriteToUDP(append(bogus, "wrong"...), client); err != nil {
		return err
	}
	_, err = udp.WriteToUDP(append(header, "good"...), client)
	return err
}

// expectBytes consumes one exact SOCKS fixture frame from the control socket.
func expectBytes(r io.Reader, want []byte) error {
	got := make([]byte, len(want))
	if _, err := io.ReadFull(r, got); err != nil {
		return err
	}
	if string(got) != string(want) {
		return errors.New("unexpected SOCKS frame")
	}
	return nil
}
