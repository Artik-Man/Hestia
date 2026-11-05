package quality

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
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
	conn, err := p.dial(ctx, strings.ToLower(c.Protocol), target)
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
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if parent.Err() == nil && ctx.Err() == context.DeadlineExceeded {
				return failure
			}
			return classify(parent, err)
		}
		var response dnsmessage.Message
		if response.Unpack(buf[:n]) != nil || !response.Response || response.ID != query.ID || response.OpCode != 0 || len(response.Questions) != 1 {
			continue
		}
		q := response.Questions[0]
		if q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET || !strings.EqualFold(q.Name.String(), name.String()) {
			continue
		}
		if response.RCode != dnsmessage.RCodeSuccess {
			return dnsError + outcome(response.RCode-1)
		}
		return success
	}
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
