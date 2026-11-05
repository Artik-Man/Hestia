package dnsservice

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// listenerResolver counts accepted requests and returns a real DNS answer large enough to require TCP retry.
type listenerResolver struct {
	calls atomic.Int64
	reply []byte
}

// Resolve returns an independent fixture without contacting any upstream.
func (r *listenerResolver) Resolve(context.Context, []byte) ([]byte, error) {
	r.calls.Add(1)
	return r.reply, nil
}

// ResolveUDP returns the canned listener response for an admitted datagram.
func (r *listenerResolver) ResolveUDP(ctx context.Context, _ netip.AddrPort, packet []byte) ([]byte, error) {
	return r.Resolve(ctx, packet)
}

// listenerPackets constructs an A query and a large DNS response to check UDP limits and stream framing.
func listenerPackets(t *testing.T) ([]byte, []byte) {
	t.Helper()
	name := dnsmessage.MustNewName("large.example.")
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 194, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	request, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	query.Response = true
	for i := 0; i < 48; i++ {
		query.Answers = append(query.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i + 1)}}})
	}
	large, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return request, large
}

// TestDNSListenerTransports exercises authorized and rejected loopback traffic on real UDP and TCP sockets.
func TestDNSListenerTransports(t *testing.T) {
	request, reply := listenerPackets(t)
	for _, transport := range []string{"udp4", "tcp4"} {
		for _, allow := range []bool{true, false} {
			label := "denied"
			if allow {
				label = "allowed"
			}
			t.Run(transport+"/"+label, func(t *testing.T) {
				router := netip.MustParseAddr("127.0.0.2")
				if allow {
					router = netip.MustParseAddr("127.0.0.1")
				}
				resolver := listenerResolver{reply: reply}
				slots := make(chan struct{}, 2)
				var active sync.WaitGroup
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				var address string
				var server io.Closer
				closed := make(chan error, 1)
				if transport == "udp4" {
					socket, err := net.ListenUDP(transport, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					address, server = socket.LocalAddr().String(), socket
					go func() { closed <- serveDatagrams(ctx, socket, router, &resolver, slots, &active) }()
				} else {
					listener, err := net.Listen(transport, "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					address, server = listener.Addr().String(), listener
					go func() { closed <- serveStreams(ctx, listener, router, &resolver, slots, &active) }()
				}
				defer func() { cancel(); server.Close(); <-closed; active.Wait() }()
				conn, err := net.DialTimeout(transport, address, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				wire := request
				if transport == "tcp4" {
					wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(request))), request...)
				}
				_, writeErr := conn.Write(wire)
				if writeErr != nil && (allow || transport == "udp4") {
					t.Fatal(writeErr)
				}
				buf := make([]byte, 4096)
				var n int
				if transport == "udp4" {
					n, err = conn.Read(buf)
				} else {
					var frame [2]byte
					_, err = io.ReadFull(conn, frame[:])
					if err == nil {
						n = int(binary.BigEndian.Uint16(frame[:]))
						if n > len(buf) {
							t.Fatal("unexpected frame length", n)
						}
						_, err = io.ReadFull(conn, buf[:n])
					}
				}
				if !allow {
					if err == nil || resolver.calls.Load() != 0 {
						t.Fatalf("unauthorized client reached resolver: calls=%d, returned %d bytes", resolver.calls.Load(), n)
					}
					return
				}
				var response dnsmessage.Message
				if err != nil || response.Unpack(buf[:n]) != nil || response.ID != 194 || !response.Response || resolver.calls.Load() != 1 {
					t.Fatalf("invalid authorized answer: len=%d err=%v", n, err)
				}
				if transport == "tcp4" && (response.Truncated || len(response.Answers) != 48) || transport == "udp4" && (!response.Truncated || n > 512 || len(response.Questions) != 1) {
					t.Fatalf("incorrect truncation/framing: len=%d, TC=%v, answers=%d", n, response.Truncated, len(response.Answers))
				}
			})
		}
	}
}

// TestDatagramEDNSLimit checks client-advertised UDP size and the server's ceiling.
func TestDatagramEDNSLimit(t *testing.T) {
	query, reply := listenerPackets(t)
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		t.Fatal(err)
	}
	request.Additionals = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: dnsmessage.Class(4096)}, Body: &dnsmessage.OPTResource{}}}
	edns, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) <= 512 || len(reply) > 1232 || len(datagramReply(edns, reply)) != len(reply) {
		t.Fatal("a full response within the advertised size was truncated")
	}
	reply = append(reply, make([]byte, 1233-len(reply))...)
	var clipped dnsmessage.Message
	if err := clipped.Unpack(datagramReply(edns, reply)); err != nil || !clipped.Truncated || len(clipped.Questions) != 1 {
		t.Fatalf("safe UDP ceiling not applied: %v", err)
	}
}
