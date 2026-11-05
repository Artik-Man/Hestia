package quality

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// pinnedPacketConn presents one connected UDP socket or SOCKS association as a QUIC packet connection.
type pinnedPacketConn struct {
	net.Conn
	peer *net.UDPAddr
}

// ReadFrom receives one datagram that the connected socket or authenticated relay matched to the target.
func (c *pinnedPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	n, err := c.Read(data)
	return n, c.peer, err
}

// WriteTo restricts QUIC to the destination for which the monitored exit established this UDP association.
func (c *pinnedPacketConn) WriteTo(data []byte, address net.Addr) (int, error) {
	peer, ok := address.(*net.UDPAddr)
	if !ok || peer.AddrPort() != c.peer.AddrPort() {
		return 0, errors.New("destination differs from the pinned QUIC path")
	}
	return c.Write(data)
}

// probeHTTP3 opens an exit-bound UDP socket and tests one authenticated HTTP/3 service exchange.
func probeHTTP3(ctx context.Context, p Path, c Check, target string) outcome {
	peer, err := netip.ParseAddrPort(target)
	if err != nil {
		return localError
	}
	config := &tls.Config{ServerName: c.ServerName, MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}
	u, err := serviceURL(c, target)
	if err != nil {
		return localError
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return localError
	}
	socket, err := p.dial(ctx, "udp", target)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return localError
		}
		return classify(context.WithoutCancel(ctx), err)
	}
	defer socket.Close()
	result := exchangeHTTP3(req, socket, net.UDPAddrFromAddrPort(peer), config)
	if ctx.Err() == context.Canceled {
		return localError
	}
	return result
}

// exchangeHTTP3 makes exactly one request over the supplied UDP path and checks the final response status.
func exchangeHTTP3(req *http.Request, socket net.Conn, peer *net.UDPAddr, config *tls.Config) outcome {
	transport := &quic.Transport{Conn: &pinnedPacketConn{Conn: socket, peer: peer}}
	defer transport.Close()
	conn, err := transport.Dial(req.Context(), peer, config, &quic.Config{DisablePathMTUDiscovery: true})
	if err != nil {
		return failure
	}
	defer conn.CloseWithError(0, "")
	client := (&http3.Transport{MaxResponseHeaderBytes: 16384, DisableCompression: true}).NewClientConn(conn)
	resp, err := client.RoundTrip(req)
	if err != nil {
		return failure
	}
	defer resp.Body.Close()
	if resp.ProtoMajor == 3 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return success
	}
	return failure
}
