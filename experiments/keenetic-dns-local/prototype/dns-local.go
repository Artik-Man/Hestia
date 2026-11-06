// Command dns-local provides a synthetic DNS responder and a strict DNS probe for the KN-1012 runtime study.
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
	responderAddress = "127.0.0.1:19250"
	proxyAddress     = "127.0.0.1:19251"
	responseAddress  = "192.0.2.42"
)

var udpQueries atomic.Uint64
var tcpQueries atomic.Uint64
var answerQueries atomic.Uint64
var nxdomainQueries atomic.Uint64

// main selects the responder or probe mode and reports failures with a nonzero exit status.
func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: dns-local responder|probe")
	}
	switch os.Args[1] {
	case "responder":
		if err := runResponder(); err != nil {
			log.Fatal(err)
		}
	case "probe":
		if err := runProbe(); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unknown mode %q; expected responder or probe", os.Args[1])
	}
}

// runResponder serves only the fixed synthetic A and NXDOMAIN records on loopback UDP and TCP.
func runResponder() error {
	udp, err := net.ListenPacket("udp4", responderAddress)
	if err != nil {
		return fmt.Errorf("listen responder UDP: %w", err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", responderAddress)
	if err != nil {
		return fmt.Errorf("listen responder TCP: %w", err)
	}
	defer tcp.Close()
	log.Printf("responder ready addr=%s", responderAddress)
	go serveUDP(udp)
	for {
		conn, err := tcp.Accept()
		if err != nil {
			return fmt.Errorf("accept responder TCP: %w", err)
		}
		go serveTCP(conn)
	}
}

// serveUDP reads bounded DNS datagrams and returns a synthetic response to each accepted query.
func serveUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("responder UDP read error: %v", err)
			return
		}
		udpQueries.Add(1)
		response, qname, rcode, err := makeResponse(buf[:n])
		if err != nil {
			log.Printf("responder UDP rejected query: %v", err)
			continue
		}
		countResponse(qname, rcode)
		if _, err := conn.WriteTo(response, addr); err != nil {
			log.Printf("responder UDP write error: %v", err)
		}
		log.Printf("responder UDP id=%d query=%s rcode=%d counters udp=%d tcp=%d answer=%d nxdomain=%d", binary.BigEndian.Uint16(buf[:2]), qname, rcode, udpQueries.Load(), tcpQueries.Load(), answerQueries.Load(), nxdomainQueries.Load())
	}
}

// serveTCP reads length-prefixed DNS messages and writes length-prefixed synthetic responses.
func serveTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		log.Printf("responder TCP frame read error: %v", err)
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, query); err != nil {
		log.Printf("responder TCP query read error: %v", err)
		return
	}
	tcpQueries.Add(1)
	response, qname, rcode, err := makeResponse(query)
	if err != nil {
		log.Printf("responder TCP rejected query: %v", err)
		return
	}
	countResponse(qname, rcode)
	binary.BigEndian.PutUint16(length[:], uint16(len(response)))
	if _, err := conn.Write(append(length[:], response...)); err != nil {
		log.Printf("responder TCP response write error: %v", err)
		return
	}
	log.Printf("responder TCP id=%d query=%s rcode=%d counters udp=%d tcp=%d answer=%d nxdomain=%d", binary.BigEndian.Uint16(query[:2]), qname, rcode, udpQueries.Load(), tcpQueries.Load(), answerQueries.Load(), nxdomainQueries.Load())
}

// countResponse increments the matching synthetic record counter for a successful parse.
func countResponse(qname string, rcode uint16) {
	if qname == "answer.dns-local.test." && rcode == 0 {
		answerQueries.Add(1)
	}
	if qname == "missing.dns-local.test." && rcode == 3 {
		nxdomainQueries.Add(1)
	}
}

// makeResponse validates a single IN A query and creates an A answer or NXDOMAIN packet.
func makeResponse(query []byte) ([]byte, string, uint16, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, "", 0, errors.New("expected one DNS question")
	}
	qname, end, err := decodeName(query, 12)
	if err != nil || end+4 > len(query) || binary.BigEndian.Uint16(query[end:end+2]) != 1 || binary.BigEndian.Uint16(query[end+2:end+4]) != 1 {
		return nil, "", 0, errors.New("expected an IN A question")
	}
	rcode := uint16(0)
	answers := uint16(1)
	if qname != "answer.dns-local.test." {
		rcode, answers = 3, 0
	}
	response := append([]byte(nil), query[:end+4]...)
	flags := binary.BigEndian.Uint16(query[2:4])
	flags = (flags | 0x8000 | 0x0080) &^ 0x0400
	flags = (flags &^ 0x000f) | rcode
	binary.BigEndian.PutUint16(response[2:4], flags)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], answers)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	if answers == 1 {
		response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 42)
	}
	return response, qname, rcode, nil
}

// decodeName decodes a simple uncompressed DNS question name and returns its next offset.
func decodeName(packet []byte, offset int) (string, int, error) {
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

// runProbe sends UDP and TCP queries to sing-box and validates IDs, questions, response codes, and A data.
func runProbe() error {
	for _, network := range []string{"udp", "tcp"} {
		for _, test := range []struct {
			name string
			want uint16
			addr string
		}{{"answer.dns-local.test.", 0, responseAddress}, {"missing.dns-local.test.", 3, ""}} {
			if err := probeOne(network, test.name, test.want, test.addr); err != nil {
				return err
			}
		}
	}
	log.Printf("probe success: UDP/TCP A and NXDOMAIN passed against %s", proxyAddress)
	return nil
}

// probeOne sends one DNS query with a deadline and validates the complete response contract.
func probeOne(network, name string, wantRCode uint16, wantAddress string) error {
	query, id, err := makeQuery(name)
	if err != nil {
		return err
	}
	var response []byte
	if network == "udp" {
		conn, err := net.DialTimeout("udp4", proxyAddress, 3*time.Second)
		if err != nil {
			return fmt.Errorf("dial proxy UDP: %w", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			return fmt.Errorf("write proxy UDP: %w", err)
		}
		response = make([]byte, 4096)
		n, err := conn.Read(response)
		if err != nil {
			return fmt.Errorf("read proxy UDP: %w", err)
		}
		response = response[:n]
	} else {
		conn, err := net.DialTimeout("tcp4", proxyAddress, 3*time.Second)
		if err != nil {
			return fmt.Errorf("dial proxy TCP: %w", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(query)))
		if _, err := conn.Write(append(length[:], query...)); err != nil {
			return fmt.Errorf("write proxy TCP: %w", err)
		}
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return fmt.Errorf("read proxy TCP frame: %w", err)
		}
		response = make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, response); err != nil {
			return fmt.Errorf("read proxy TCP response: %w", err)
		}
	}
	if err := validateResponse(response, id, name, wantRCode, wantAddress); err != nil {
		return fmt.Errorf("%s %s: %w", strings.ToUpper(network), name, err)
	}
	log.Printf("probe pass network=%s id=%d name=%s type=A rcode=%d address=%s", strings.ToUpper(network), id, name, wantRCode, wantAddress)
	return nil
}

// makeQuery creates a recursive IN A query with a unique fixed ID derived from the current nanosecond time.
func makeQuery(name string) ([]byte, uint16, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	query := make([]byte, 12)
	id := uint16(time.Now().UnixNano())
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, 0, fmt.Errorf("invalid DNS label %q", label)
		}
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query, id, nil
}

// validateResponse verifies transaction ID, question name/type/class, RCODE, answer count, and A address.
func validateResponse(response []byte, id uint16, name string, wantRCode uint16, wantAddress string) error {
	if len(response) < 12 || binary.BigEndian.Uint16(response[0:2]) != id {
		return errors.New("missing response or transaction ID mismatch")
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x0200 != 0 || flags&0x000f != wantRCode || binary.BigEndian.Uint16(response[4:6]) != 1 {
		return fmt.Errorf("unexpected DNS flags/rcode/question count: flags=%04x qd=%d", flags, binary.BigEndian.Uint16(response[4:6]))
	}
	gotName, offset, err := decodeName(response, 12)
	if err != nil || gotName != strings.ToLower(name) || offset+4 > len(response) || binary.BigEndian.Uint16(response[offset:offset+2]) != 1 || binary.BigEndian.Uint16(response[offset+2:offset+4]) != 1 {
		return fmt.Errorf("DNS question mismatch: got=%s", gotName)
	}
	answers := binary.BigEndian.Uint16(response[6:8])
	if wantRCode == 3 && answers != 0 {
		return fmt.Errorf("NXDOMAIN had %d answers", answers)
	}
	if wantRCode == 0 {
		if answers != 1 || offset+4+16 > len(response) {
			return fmt.Errorf("A response answer count/length mismatch: answers=%d", answers)
		}
		answer := response[offset+4:]
		if answer[0] != 0xc0 || answer[1] != 0x0c || binary.BigEndian.Uint16(answer[2:4]) != 1 || binary.BigEndian.Uint16(answer[4:6]) != 1 || binary.BigEndian.Uint16(answer[10:12]) != 4 {
			return errors.New("A answer record shape mismatch")
		}
		if got := net.IP(answer[12:16]).String(); got != wantAddress {
			return fmt.Errorf("A answer mismatch: got=%s want=%s", got, wantAddress)
		}
	}
	return nil
}

// init validates that no command-line flag parsing is inherited into the two-mode tool.
func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}
