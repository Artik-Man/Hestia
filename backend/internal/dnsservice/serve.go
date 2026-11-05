package dnsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// responder resolves one DNS request received on the authorized router-facing listener.
type responder interface {
	Resolve(context.Context, []byte) ([]byte, error)
	ResolveUDP(context.Context, netip.AddrPort, []byte) ([]byte, error)
}

// serve binds TCP and UDP to the same address and admits only packets from the configured router.
func serve(ctx context.Context, address netip.AddrPort, router netip.Addr, resolver responder, ready func(netip.AddrPort)) error {
	var listen net.ListenConfig
	tcp, err := listen.Listen(ctx, "tcp4", address.String())
	if err != nil {
		return err
	}
	defer tcp.Close()
	socket, err := listen.ListenPacket(ctx, "udp4", tcp.Addr().String())
	if err != nil {
		return err
	}
	defer socket.Close()
	ctx, cancel := context.WithCancel(ctx)
	var pending sync.WaitGroup
	defer pending.Wait()
	defer cancel()
	stop := context.AfterFunc(ctx, func() { tcp.Close(); socket.Close() })
	defer stop()
	slots := make(chan struct{}, 96)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer func() { cancel(); tcp.Close(); socket.Close() }()
	errs := make(chan error, 2)
	workers.Add(2)
	go func() {
		defer workers.Done()
		errs <- serveDatagrams(ctx, socket.(*net.UDPConn), router, resolver, slots, &pending)
	}()
	go func() { defer workers.Done(); errs <- serveStreams(ctx, tcp, router, resolver, slots, &pending) }()
	ready(tcp.Addr().(*net.TCPAddr).AddrPort())
	select {
	case <-ctx.Done():
		return nil
	case err = <-errs:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

// serveDatagrams drops unauthorized datagrams before allocating a worker and bounds in-flight work.
func serveDatagrams(ctx context.Context, socket *net.UDPConn, router netip.Addr, resolver responder, slots chan struct{}, pending *sync.WaitGroup) error {
	buf := make([]byte, 65535)
	for {
		n, peer, err := socket.ReadFromUDPAddrPort(buf)
		if err != nil {
			return err
		}
		if peer.Addr().Unmap() != router || n < 12 {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		pending.Add(1)
		go func() {
			defer pending.Done()
			defer func() { <-slots }()
			request, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			response, err := resolver.ResolveUDP(request, peer, packet)
			if err == nil && len(response) > 0 {
				if response = datagramReply(packet, response); len(response) > 0 {
					_, _ = socket.WriteToUDPAddrPort(response, peer)
				}
			}
		}()
	}
}

// datagramReply honors the requestor's EDNS limit and caps UDP packets at 1232 bytes for safe delivery.
func datagramReply(query, response []byte) []byte {
	if len(response) <= 512 {
		return response
	}
	var request dnsmessage.Message
	if request.Unpack(query) != nil {
		return nil
	}
	limit := 512
	for _, rr := range request.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			limit = max(512, min(1232, int(rr.Header.Class)))
			break
		}
	}
	if len(response) <= limit {
		return response
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil {
		return nil
	}
	header.Truncated = true
	message := dnsmessage.Message{Header: header, Questions: request.Questions}
	data, _ := message.Pack()
	return data
}

// serveStreams handles length-prefixed DNS with bounded connection lifetime and per-query timeouts.
func serveStreams(ctx context.Context, listener net.Listener, router netip.Addr, resolver responder, slots chan struct{}, pending *sync.WaitGroup) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		if conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap() != router {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stop := context.AfterFunc(ctx, func() { conn.Close() })
			defer stop()
			if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
				return
			}
			var size [2]byte
			for i := 0; i < 64; i++ {
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(size[:]))
				if n < 12 {
					return
				}
				packet := make([]byte, n)
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				request, cancel := context.WithTimeout(ctx, 5*time.Second)
				reply, err := resolver.Resolve(request, packet)
				cancel()
				if err != nil || len(reply) < 12 || len(reply) > 65535 {
					return
				}
				binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
				if _, err = conn.Write(append(size[:], reply...)); err != nil {
					return
				}
			}
		}()
	}
}

// validateListener restricts router-facing DNS to an explicit local/private IPv4 listener and one peer.
func validateListener(address netip.AddrPort, router netip.Addr) error {
	for _, ip := range []netip.Addr{address.Addr(), router} {
		if !ip.Is4() || !(ip.IsPrivate() || ip.IsLoopback()) {
			return errors.New("DNS listener and router must be private or loopback IPv4 addresses")
		}
	}
	if address.Port() == 0 {
		return errors.New("DNS listener port must be positive")
	}
	return nil
}
