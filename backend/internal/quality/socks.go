package quality

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// remoteFailure represents a negative SOCKS reply about the requested external TCP target.
type remoteFailure struct{ error }

// setupFailure identifies an issue reaching or authenticating to the local exit-specific relay.
type setupFailure struct{ error }

// dialSOCKS authenticates to an exit-specific loopback SOCKS5 endpoint, with no unbound fallback.
func dialSOCKS(ctx context.Context, p Path, network, target string) (net.Conn, error) {
	ep, err := netip.ParseAddrPort(p.SocksAddress)
	if err != nil || !ep.Addr().IsLoopback() || len(p.SocksPassword) == 0 || len(p.SocksPassword) > 255 {
		return nil, errors.New("invalid local quality relay")
	}
	dst, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil, err
	}
	ctrl, err := new(net.Dialer).DialContext(ctx, "tcp", p.SocksAddress)
	if err != nil {
		return nil, &setupFailure{err}
	}
	keep := false
	defer func() {
		if !keep {
			_ = ctrl.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = ctrl.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := ctrl.SetDeadline(deadline); err != nil {
		return nil, &setupFailure{err}
	}
	if err = authenticate(ctrl, p.SocksPassword); err != nil {
		return nil, &setupFailure{err}
	}
	command := byte(1)
	addr := dst
	if network == "udp" {
		command = 3
		addr = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	req := append([]byte{5, command, 0}, socksEndpoint(addr)...)
	if _, err := ctrl.Write(req); err != nil {
		return nil, &setupFailure{err}
	}
	var header [3]byte
	if _, err := io.ReadFull(ctrl, header[:]); err != nil {
		// After CONNECT the local proxy waits for the remote TCP handshake.
		var ne net.Error
		if command == 1 && (errors.As(err, &ne) && ne.Timeout() || ctx.Err() == context.DeadlineExceeded) {
			return nil, &remoteFailure{err}
		}
		return nil, &setupFailure{err}
	}
	if header[0] != 5 || header[2] != 0 {
		return nil, errors.New("invalid SOCKS reply")
	}
	if code := header[1]; code != 0 {
		err := errors.New("SOCKS reply " + strconv.Itoa(int(code)))
		if command == 1 && code >= 3 && code <= 6 {
			return nil, &remoteFailure{err}
		}
		return nil, &setupFailure{err}
	}
	relay, err := readEndpoint(ctrl)
	if err != nil {
		return nil, &setupFailure{err}
	}
	if command == 1 {
		keep = true
		return ctrl, nil
	}
	if relay.Addr().IsUnspecified() {
		relay = netip.AddrPortFrom(ep.Addr(), relay.Port())
	}
	if !relay.Addr().IsLoopback() || relay.Port() == 0 {
		return nil, errors.New("invalid local UDP relay")
	}
	udp, err := new(net.Dialer).DialContext(ctx, "udp", relay.String())
	if err != nil {
		return nil, &setupFailure{err}
	}
	keep = true
	return &relayConn{Conn: udp, control: ctrl, header: append([]byte{0, 0, 0}, socksEndpoint(dst)...), target: dst}, nil
}

// authenticate permits only RFC 1929 username/password negotiation with the local sing-box listener.
func authenticate(conn net.Conn, password string) error {
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, 2} {
		return errors.New("quality relay requires authenticated SOCKS")
	}
	const user = "hestia-quality"
	req := append([]byte{1, byte(len(user))}, user...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{1, 0} {
		return errors.New("quality relay authentication failed")
	}
	return nil
}

// socksEndpoint encodes the exact IP and port without allowing proxy-side name resolution.
func socksEndpoint(ep netip.AddrPort) []byte {
	ip := ep.Addr().Unmap()
	typ := byte(4)
	if ip.Is4() {
		typ = 1
	}
	addr := append([]byte{typ}, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(addr, ep.Port())
}

// readEndpoint decodes a literal relay address or datagram source from its SOCKS wire form.
func readEndpoint(r io.Reader) (netip.AddrPort, error) {
	var buf [18]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return netip.AddrPort{}, err
	}
	n := 0
	switch buf[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	default:
		return netip.AddrPort{}, errors.New("SOCKS relay requires a literal address")
	}
	if _, err := io.ReadFull(r, buf[:n+2]); err != nil {
		return netip.AddrPort{}, err
	}
	addr, _ := netip.AddrFromSlice(buf[:n])
	return netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(buf[n:n+2])), nil
}

type relayConn struct {
	net.Conn
	control net.Conn
	header  []byte
	target  netip.AddrPort
}

// Close releases the UDP socket and its associated authenticated control connection.
func (c *relayConn) Close() error { return errors.Join(c.Conn.Close(), c.control.Close()) }

// Write sends the payload in one SOCKS datagram directed to the original target.
func (c *relayConn) Write(b []byte) (int, error) {
	packet := make([]byte, 0, len(c.header)+len(b))
	packet = append(packet, c.header...)
	packet = append(packet, b...)
	n, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

// Read ignores fragments and datagrams from unexpected endpoints until the caller's deadline.
func (c *relayConn) Read(b []byte) (int, error) {
	packet := make([]byte, len(b)+22)
	for {
		n, err := c.Conn.Read(packet)
		if err != nil {
			return 0, err
		}
		if n < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
			continue
		}
		body := bytes.NewReader(packet[3:n])
		from, err := readEndpoint(body)
		if err != nil || from.Port() != c.target.Port() || from.Addr() != c.target.Addr().Unmap() {
			continue
		}
		return body.Read(b)
	}
}
