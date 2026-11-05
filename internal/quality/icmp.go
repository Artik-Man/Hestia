package quality

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// probeICMP sends a scoped echo with a random correlation token; a SOCKS relay cannot carry raw ICMP.
func probeICMP(ctx context.Context, p Path, target string) outcome {
	if p.SocksAddress != "" {
		return localError
	}
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return localError
	}
	addr = addr.Unmap()
	network, proto := "ip4:icmp", 1
	var reqType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if addr.Is6() {
		network, proto = "ip6:ipv6-icmp", 58
		reqType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	conn, err := p.dial(ctx, network, addr.String())
	if err != nil {
		return classify(context.WithoutCancel(ctx), err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return localError
	}
	var token [20]byte
	if _, err = rand.Read(token[:]); err != nil {
		return localError
	}
	echo := icmp.Echo{ID: int(binary.BigEndian.Uint16(token[:2])), Seq: int(binary.BigEndian.Uint16(token[2:4])), Data: token[4:]}
	msg := icmp.Message{Type: reqType, Body: &echo}
	out, err := msg.Marshal(nil)
	if err != nil {
		return localError
	}
	if _, err = conn.Write(out); err != nil {
		return classify(context.WithoutCancel(ctx), err)
	}
	buf := make([]byte, 1500)
	for {
		var n int
		if raw, ok := conn.(*net.IPConn); ok {
			// ReadFromIP removes the IPv4 header that Read on a Linux raw socket retains.
			var source *net.IPAddr
			n, source, err = raw.ReadFromIP(buf)
			if err == nil && (source == nil || !source.IP.Equal(net.IP(addr.AsSlice()))) {
				continue
			}
		} else {
			n, err = conn.Read(buf)
		}
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return failure
			}
			return classify(ctx, err)
		}
		reply, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || reply.Type != replyType || reply.Code != 0 {
			continue
		}
		e, ok := reply.Body.(*icmp.Echo)
		if ok && e.ID == echo.ID && e.Seq == echo.Seq && bytes.Equal(e.Data, echo.Data) {
			return success
		}
	}
}
