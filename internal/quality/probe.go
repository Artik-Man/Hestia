package quality

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Path identifies a confined route; the worker must supply one per configured exit including reserves.
type Path struct {
	ID            string                                                  `json:"id"`
	Device        string                                                  `json:"device,omitempty"`
	Mark          int                                                     `json:"mark,omitempty"`
	SocksAddress  string                                                  `json:"socksAddress,omitempty"`
	SocksPassword string                                                  `json:"socksPassword,omitempty"`
	DialContext   func(context.Context, string, string) (net.Conn, error) `json:"-"`
}

type outcome uint8

const (
	localError outcome = iota
	failure
	success
	dnsError
)

// dial establishes only an explicitly confined connection. Missing route metadata fails closed.
func (p Path) dial(ctx context.Context, network, target string) (net.Conn, error) {
	if p.DialContext != nil {
		return p.DialContext(ctx, network, target)
	}
	if p.SocksAddress != "" {
		return dialSOCKS(ctx, p, network, target)
	}
	if p.Device == "" {
		return nil, errors.New("missing quality probe interface")
	}
	dialer := net.Dialer{Control: bindPath(p)}
	return dialer.DialContext(ctx, network, target)
}

// probe runs one transport exchange, excluding local setup errors and cancellation from the score.
func probe(parent context.Context, p Path, c Check, target string) outcome {
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.TimeoutSeconds)*time.Second)
	defer cancel()
	switch c.Protocol {
	case HTTP3:
		return probeHTTP3(ctx, p, c, target)
	case HTTPS:
		return probeHTTPS(ctx, p, c, target)
	case ICMP:
		return probeICMP(ctx, p, target)
	case UDP, DNS, TCP:
	default:
		return localError
	}
	network := "udp"
	if c.Protocol == TCP {
		network = "tcp"
	}
	conn, err := p.dial(ctx, network, target)
	if err != nil {
		return classify(parent, err)
	}
	defer conn.Close()
	if c.Protocol == TCP {
		return success
	}
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return localError
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var bits [2]byte
	if _, err := rand.Read(bits[:]); err != nil {
		return localError
	}
	name, err := dnsmessage.NewName(strings.TrimSuffix(c.DNSName, ".") + ".")
	if err != nil {
		return localError
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(bits[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, err := query.Pack()
	if err != nil {
		return localError
	}
	if _, err = conn.Write(packet); err != nil {
		return classify(parent, err)
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if parent.Err() == nil && ctx.Err() == context.DeadlineExceeded {
				return failure
			}
			return classify(parent, err)
		}
		var response dnsmessage.Message
		if response.Unpack(buf[:n]) != nil || !matchesQuery(&response, &query) {
			continue
		}
		if response.Truncated && c.Protocol == DNS {
			return resolveTCP(ctx, p, target, packet, &query)
		}
		return dnsOutcome(&response, c.Protocol)
	}
}

// matchesQuery ties a DNS reply to the outstanding A/IN question and transaction.
func matchesQuery(response, query *dnsmessage.Message) bool {
	if !response.Response || response.ID != query.ID || response.OpCode != 0 || len(response.Questions) != 1 {
		return false
	}
	q := response.Questions[0]
	return q.Class == dnsmessage.ClassINET && q.Type == dnsmessage.TypeA && strings.EqualFold(q.Name.String(), query.Questions[0].Name.String())
}

// dnsOutcome distinguishes proof of a UDP exchange from successful resolution of the requested name.
func dnsOutcome(response *dnsmessage.Message, protocol string) outcome {
	if response.RCode != dnsmessage.RCodeSuccess {
		return dnsError + outcome(response.RCode-1)
	}
	if protocol == UDP {
		return success
	}
	if response.Truncated {
		return failure
	}
	name := strings.ToLower(response.Questions[0].Name.String())
	aliases := map[string]string{}
	addresses := map[string]bool{}
	for _, answer := range response.Answers {
		if answer.Header.Class != dnsmessage.ClassINET {
			continue
		}
		owner := strings.ToLower(answer.Header.Name.String())
		switch data := answer.Body.(type) {
		case *dnsmessage.AResource:
			addr := netip.AddrFrom4(data.A)
			if addr.IsGlobalUnicast() {
				addresses[owner] = true
			}
		case *dnsmessage.CNAMEResource:
			aliases[owner] = strings.ToLower(data.CNAME.String())
		}
	}
	for name != "" {
		if addresses[name] {
			return success
		}
		next := aliases[name]
		delete(aliases, name)
		name = next
	}
	return failure
}

// resolveTCP follows a truncated resolver answer once on the same pinned path and within the original deadline.
func resolveTCP(ctx context.Context, p Path, target string, packet []byte, query *dnsmessage.Message) outcome {
	conn, err := p.dial(ctx, "tcp", target)
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
	request := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	if _, err = conn.Write(append(request, packet...)); err != nil {
		return classify(context.WithoutCancel(ctx), err)
	}
	var length [2]byte
	if _, err = io.ReadFull(conn, length[:]); err != nil {
		return classify(context.WithoutCancel(ctx), err)
	}
	reply := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err = io.ReadFull(conn, reply); err != nil {
		return classify(context.WithoutCancel(ctx), err)
	}
	var response dnsmessage.Message
	if response.Unpack(reply) != nil || !matchesQuery(&response, query) {
		return failure
	}
	return dnsOutcome(&response, DNS)
}

// classify separates an attempted but unsuccessful transport exchange from a local measurement failure.
func classify(parent context.Context, err error) outcome {
	if parent.Err() != nil {
		return localError
	}
	var remote *remoteFailure
	if errors.As(err, &remote) {
		return failure
	}
	var setup *setupFailure
	if errors.As(err, &setup) {
		return localError
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) {
		return failure
	}
	return localError
}

// DialExit opens a connection through this exit's bound device or authenticated relay.
// It has no system-resolver fallback. Callers supply a literal destination and a deadline.
func (p Path) DialExit(ctx context.Context, network, target string) (net.Conn, error) {
	if _, err := netip.ParseAddrPort(target); err != nil || (network != "udp" && network != "tcp") {
		return nil, errors.New("invalid exit destination")
	}
	return p.dial(ctx, network, target)
}
