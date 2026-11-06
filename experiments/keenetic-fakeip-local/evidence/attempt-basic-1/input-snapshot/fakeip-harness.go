// Command fakeip-harness supplies loopback DNS and TCP/UDP markers for the KN-1012 FakeIP study.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	domainName = "service.fakeip-local.test."
	dnsAddress = "127.0.0.1:19352"
	dnsProxy   = "127.0.0.1:19351"
	socksProxy = "127.0.0.1:19350"
	tcpAddress = "127.0.0.1:19353"
	udpAddress = "127.0.0.1:19354"
	tcpMarker  = "HSTIA-FAKEIP-TCP-19353"
	udpMarker  = "HSTIA-FAKEIP-UDP-19354"
)

var dnsCount atomic.Uint64
var tcpCount atomic.Uint64
var udpCount atomic.Uint64

// main dispatches the bounded marker server or a DNS/SOCKS probe and exits nonzero on failure.
func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: fakeip-harness serve|probe|resume")
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(); err != nil {
			log.Fatal(err)
		}
	case "probe":
		if err := probe(true); err != nil {
			log.Fatal(err)
		}
	case "resume":
		if err := probe(false); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("expected serve, probe, or resume")
	}
}

// serve opens only the reserved loopback DNS and marker listeners and serves until its process is stopped.
func serve() error {
	dnsUDP, err := net.ListenPacket("udp4", dnsAddress)
	if err != nil {
		return fmt.Errorf("listen synthetic DNS UDP: %w", err)
	}
	defer dnsUDP.Close()
	dnsTCP, err := net.Listen("tcp4", dnsAddress)
	if err != nil {
		return fmt.Errorf("listen synthetic DNS TCP: %w", err)
	}
	defer dnsTCP.Close()
	markerTCP, err := net.Listen("tcp4", tcpAddress)
	if err != nil {
		return fmt.Errorf("listen TCP marker: %w", err)
	}
	defer markerTCP.Close()
	markerUDP, err := net.ListenPacket("udp4", udpAddress)
	if err != nil {
		return fmt.Errorf("listen UDP marker: %w", err)
	}
	defer markerUDP.Close()
	log.Printf("ready dns=%s tcp=%s udp=%s", dnsAddress, tcpAddress, udpAddress)
	go serveDNSUDP(dnsUDP)
	go serveDNSTCP(dnsTCP)
	go serveMarkerTCP(markerTCP)
	serveMarkerUDP(markerUDP)
	return nil
}

// serveDNSUDP returns only a synthetic A record mapping the study hostname to loopback.
func serveDNSUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("DNS UDP read error: %v", err)
			return
		}
		response, name, err := dnsAnswer(buf[:n])
		if err != nil {
			log.Printf("DNS UDP reject: %v", err)
			continue
		}
		dnsCount.Add(1)
		if _, err = conn.WriteTo(response, addr); err != nil {
			log.Printf("DNS UDP write error: %v", err)
		}
		log.Printf("synthetic DNS transport=UDP name=%s answer=127.0.0.1 count=%d", name, dnsCount.Load())
	}
}

// serveDNSTCP handles one length-prefixed DNS query per accepted loopback connection.
func serveDNSTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("DNS TCP accept error: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			var length [2]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				log.Printf("DNS TCP frame read error: %v", err)
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(length[:]))
			if _, err := io.ReadFull(conn, query); err != nil {
				log.Printf("DNS TCP query read error: %v", err)
				return
			}
			response, name, err := dnsAnswer(query)
			if err != nil {
				log.Printf("DNS TCP reject: %v", err)
				return
			}
			dnsCount.Add(1)
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			if _, err := conn.Write(append(length[:], response...)); err != nil {
				log.Printf("DNS TCP write error: %v", err)
				return
			}
			log.Printf("synthetic DNS transport=TCP name=%s answer=127.0.0.1 count=%d", name, dnsCount.Load())
		}()
	}
}

// serveMarkerTCP returns the fixed TCP marker to any bounded loopback connection.
func serveMarkerTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP marker accept error: %v", err)
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			tcpCount.Add(1)
			_, _ = io.WriteString(conn, tcpMarker)
			log.Printf("TCP marker served=%s count=%d", tcpMarker, tcpCount.Load())
		}()
	}
}

// serveMarkerUDP returns the fixed UDP marker to any bounded loopback datagram.
func serveMarkerUDP(conn net.PacketConn) {
	buf := make([]byte, 1024)
	for {
		_, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP marker read error: %v", err)
			return
		}
		udpCount.Add(1)
		if _, err := conn.WriteTo([]byte(udpMarker), addr); err != nil {
			log.Printf("UDP marker write error: %v", err)
		}
		log.Printf("UDP marker served=%s count=%d", udpMarker, udpCount.Load())
	}
}

// dnsAnswer validates a single IN A question for the exact synthetic name and answers loopback with TTL 30.
func dnsAnswer(query []byte) ([]byte, string, error) {
	name, end, err := decodeName(query, 12)
	if err != nil || len(query) < end+4 || binary.BigEndian.Uint16(query[4:6]) != 1 || binary.BigEndian.Uint16(query[end:end+2]) != 1 || binary.BigEndian.Uint16(query[end+2:end+4]) != 1 || name != domainName {
		return nil, name, errors.New("expected one IN A query for the exact study hostname")
	}
	response := append([]byte(nil), query[:end+4]...)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags = (flags | 0x8000 | 0x0080) &^ 0x0400
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1)
	return response, name, nil
}

// decodeName decodes the uncompressed DNS question name and returns its next packet offset.
func decodeName(packet []byte, offset int) (string, int, error) {
	if len(packet) < 12 || offset >= len(packet) {
		return "", 0, errors.New("short DNS packet")
	}
	var labels []string
	for offset < len(packet) {
		length := int(packet[offset])
		offset++
		if length == 0 {
			return strings.ToLower(strings.Join(labels, ".")) + ".", offset, nil
		}
		if length&0xc0 != 0 || length > 63 || offset+length > len(packet) {
			return "", 0, errors.New("unsupported or malformed DNS label")
		}
		labels = append(labels, string(packet[offset:offset+length]))
		offset += length
	}
	return "", 0, errors.New("unterminated DNS name")
}

// probe performs one fresh FakeIP lookup or reuses the previously recorded numeric address, then checks TCP and UDP SOCKS flows.
func probe(resolve bool) error {
	var fakeIP net.IP
	if resolve {
		answer, err := lookupFakeIP(domainName)
		if err != nil {
			return fmt.Errorf("FakeIP DNS lookup: %w", err)
		}
		fakeIP = answer
		if err := os.WriteFile("fakeip.txt", []byte(fakeIP.String()+"\n"), 0600); err != nil {
			return fmt.Errorf("save observed FakeIP: %w", err)
		}
		log.Printf("client DNS query name=%s returned_fakeip=%s", domainName, fakeIP)
	} else {
		data, err := os.ReadFile("fakeip.txt")
		if err != nil {
			return fmt.Errorf("read first-run FakeIP: %w", err)
		}
		fakeIP = net.ParseIP(strings.TrimSpace(string(data))).To4()
		if fakeIP == nil {
			return errors.New("saved value is not IPv4")
		}
		log.Printf("client reuses_saved_fakeip=%s without DNS lookup", fakeIP)
	}
	if err := socksTCP(fakeIP, 19353); err != nil {
		return err
	}
	if err := socksUDP(fakeIP, 19354); err != nil {
		return err
	}
	log.Printf("probe success fakeip=%s TCP=%s UDP=%s", fakeIP, tcpMarker, udpMarker)
	return nil
}

// lookupFakeIP requests one A record through the loopback DNS inbound and returns the response address.
func lookupFakeIP(name string) (net.IP, error) {
	query, id, err := makeQuery(name)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("udp4", dnsProxy, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial DNS inbound: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("write DNS query: %w", err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("read DNS answer: %w", err)
	}
	ip, err := parseA(response[:n], id, name)
	if err != nil {
		return nil, err
	}
	return ip, nil
}

// parseA checks transaction, response status, echoed question and one IPv4 A answer.
func parseA(packet []byte, id uint16, name string) (net.IP, error) {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[:2]) != id || binary.BigEndian.Uint16(packet[2:4])&0x8000 == 0 || binary.BigEndian.Uint16(packet[6:8]) != 1 {
		return nil, errors.New("invalid DNS response header or answer count")
	}
	gotName, offset, err := decodeName(packet, 12)
	if err != nil || gotName != name || len(packet) < offset+4 || binary.BigEndian.Uint16(packet[offset:offset+2]) != 1 || binary.BigEndian.Uint16(packet[offset+2:offset+4]) != 1 {
		return nil, errors.New("DNS response question mismatch")
	}
	offset += 4
	if offset+16 > len(packet) || packet[offset] != 0xc0 || packet[offset+1] != 0x0c || binary.BigEndian.Uint16(packet[offset+2:offset+4]) != 1 || binary.BigEndian.Uint16(packet[offset+4:offset+6]) != 1 || binary.BigEndian.Uint16(packet[offset+10:offset+12]) != 4 {
		return nil, errors.New("DNS response did not contain the expected compressed IPv4 answer")
	}
	return net.IPv4(packet[offset+12], packet[offset+13], packet[offset+14], packet[offset+15]), nil
}

// socksTCP connects to the numeric FakeIP and validates the exact TCP marker on the requested marker port.
func socksTCP(fakeIP net.IP, port uint16) error {
	conn, err := socksConnect(fakeIP, port)
	if err != nil {
		return fmt.Errorf("SOCKS TCP to FakeIP: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	data := make([]byte, len(tcpMarker))
	if _, err := io.ReadFull(conn, data); err != nil {
		return fmt.Errorf("read TCP marker: %w", err)
	}
	if string(data) != tcpMarker {
		return fmt.Errorf("unexpected TCP marker %q", data)
	}
	log.Printf("TCP over SOCKS numeric_fakeip=%s:%d marker=%s", fakeIP, port, data)
	return nil
}

// socksConnect performs a SOCKS5 no-auth CONNECT request using an IPv4 numeric destination.
func socksConnect(ip net.IP, port uint16) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", socksProxy, 3*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		conn.Close()
		return nil, err
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != [2]byte{5, 0} {
		conn.Close()
		return nil, fmt.Errorf("SOCKS greeting failed: %v reply=%v", err, reply)
	}
	request := []byte{5, 1, 0, 1}
	request = append(request, ip.To4()...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		conn.Close()
		return nil, err
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		conn.Close()
		return nil, err
	}
	if header[0] != 5 || header[1] != 0 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS CONNECT rejected: %v", header)
	}
	if err := discardSocksAddress(conn, header[3]); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socksUDP establishes a SOCKS5 UDP association and verifies the exact UDP marker from the numeric FakeIP.
func socksUDP(fakeIP net.IP, port uint16) error {
	control, err := net.DialTimeout("tcp4", socksProxy, 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS UDP control: %w", err)
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(control, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		return fmt.Errorf("SOCKS UDP greeting failed: %v reply=%v", err, greeting)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	var header [4]byte
	if _, err := io.ReadFull(control, header[:]); err != nil {
		return fmt.Errorf("SOCKS UDP ASSOCIATE: %w", err)
	}
	if header[0] != 5 || header[1] != 0 || header[3] != 1 {
		return fmt.Errorf("SOCKS UDP ASSOCIATE rejected: %v", header)
	}
	var relayBytes [6]byte
	if _, err := io.ReadFull(control, relayBytes[:]); err != nil {
		return err
	}
	relayIP := net.IPv4(relayBytes[0], relayBytes[1], relayBytes[2], relayBytes[3])
	relayPort := binary.BigEndian.Uint16(relayBytes[4:6])
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.DialTimeout("udp4", net.JoinHostPort(relayIP.String(), fmt.Sprint(relayPort)), 3*time.Second)
	if err != nil {
		return fmt.Errorf("dial SOCKS UDP relay: %w", err)
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(4 * time.Second))
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, fakeIP.To4()...)
	packet = append(packet, byte(port>>8), byte(port))
	packet = append(packet, []byte("fakeip-udp-probe")...)
	if _, err := udp.Write(packet); err != nil {
		return fmt.Errorf("send SOCKS UDP datagram: %w", err)
	}
	response := make([]byte, 1024)
	n, err := udp.Read(response)
	if err != nil {
		return fmt.Errorf("read SOCKS UDP reply: %w", err)
	}
	if n < 10 || response[0] != 0 || response[1] != 0 || response[2] != 0 || response[3] != 1 || string(response[10:n]) != udpMarker {
		return fmt.Errorf("unexpected SOCKS UDP response %q", response[:n])
	}
	log.Printf("UDP over SOCKS numeric_fakeip=%s:%d marker=%s", fakeIP, port, response[10:n])
	return nil
}

// discardSocksAddress consumes the variable address and port fields in a SOCKS5 reply.
func discardSocksAddress(conn net.Conn, addressType byte) error {
	var size int
	switch addressType {
	case 1:
		size = 4
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return err
		}
		size = int(length[0])
	case 4:
		size = 16
	default:
		return fmt.Errorf("unknown SOCKS address type %d", addressType)
	}
	if _, err := io.CopyN(io.Discard, conn, int64(size+2)); err != nil {
		return fmt.Errorf("read SOCKS bound address: %w", err)
	}
	return nil
}

// makeQuery builds a single recursive IN A query with a time-derived transaction identifier.
func makeQuery(name string) ([]byte, uint16, error) {
	query := make([]byte, 12)
	id := uint16(time.Now().UnixNano())
	binary.BigEndian.PutUint16(query[:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label %q", label)
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query, id, nil
}

// init documents and parses the per-process mode flags used by helper subcommands.
func init() {
	flag.CommandLine.SetOutput(io.Discard)
}
