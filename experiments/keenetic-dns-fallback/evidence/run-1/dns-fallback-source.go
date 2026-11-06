// Command dns-fallback runs a synthetic DNS authority or probes the local sing-box DNS inbound.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	responderAddress = "127.0.0.1:19350"
	proxyAddress     = "127.0.0.1:19351"
	chainName        = "chain.dns-fallback.test."
	aliasName        = "alias.dns-fallback.test."
	truncatedName    = "truncated.dns-fallback.test."
	chainAddress     = "192.0.2.61"
	tcpAddress       = "192.0.2.62"
)

var udpQueries atomic.Uint64
var tcpQueries atomic.Uint64
var tcUDPQueries atomic.Uint64
var chainQueries atomic.Uint64
var aliasQueries atomic.Uint64
var tcpFallbackQueries atomic.Uint64

// main dispatches one bounded helper mode and exits nonzero when setup or validation fails.
func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: dns-fallback responder|probe")
	}
	var err error
	switch os.Args[1] {
	case "responder":
		err = runResponder()
	case "probe":
		err = runProbe()
	default:
		err = fmt.Errorf("unknown mode %q; expected responder or probe", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

// runResponder binds only the reserved loopback UDP and TCP ports and serves fixed synthetic records.
func runResponder() error {
	udp, err := net.ListenPacket("udp4", responderAddress)
	if err != nil {
		return fmt.Errorf("listen UDP responder: %w", err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", responderAddress)
	if err != nil {
		return fmt.Errorf("listen TCP responder: %w", err)
	}
	defer tcp.Close()
	log.Printf("responder ready addr=%s", responderAddress)
	go serveUDP(udp)
	for {
		conn, err := tcp.Accept()
		if err != nil {
			return fmt.Errorf("accept TCP query: %w", err)
		}
		go serveTCP(conn)
	}
}

// serveUDP answers valid synthetic DNS questions and records transport, name, TC state, and counters.
func serveUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("UDP read error: %v", err)
			return
		}
		udpQueries.Add(1)
		response, name, tc, err := makeResponse(buf[:n], false)
		if err != nil {
			log.Printf("UDP rejected query: %v", err)
			continue
		}
		countQuery("UDP", name, tc)
		if _, err := conn.WriteTo(response, addr); err != nil {
			log.Printf("UDP write error: %v", err)
			continue
		}
		logCounters("UDP", name, tc)
	}
}

// serveTCP reads one length-prefixed DNS request and returns its full synthetic answer.
func serveTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		log.Printf("TCP frame read error: %v", err)
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, query); err != nil {
		log.Printf("TCP query read error: %v", err)
		return
	}
	tcpQueries.Add(1)
	response, name, tc, err := makeResponse(query, true)
	if err != nil {
		log.Printf("TCP rejected query: %v", err)
		return
	}
	countQuery("TCP", name, tc)
	binary.BigEndian.PutUint16(length[:], uint16(len(response)))
	if _, err := conn.Write(append(length[:], response...)); err != nil {
		log.Printf("TCP write error: %v", err)
		return
	}
	logCounters("TCP", name, tc)
}

// makeResponse accepts one IN A question and emits a CNAME, terminal A, deliberate TC, or TCP retry answer.
func makeResponse(packet []byte, tcp bool) ([]byte, string, bool, error) {
	var query dnsmessage.Message
	if err := query.Unpack(packet); err != nil {
		return nil, "", false, fmt.Errorf("unpack DNS query: %w", err)
	}
	if query.Response || len(query.Questions) != 1 {
		return nil, "", false, errors.New("expected one DNS question")
	}
	question := query.Questions[0]
	name := strings.ToLower(question.Name.String())
	if question.Type != dnsmessage.TypeA || question.Class != dnsmessage.ClassINET {
		return nil, name, false, errors.New("expected IN A question")
	}
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true},
		Questions: query.Questions,
	}
	var err error
	switch {
	case name == chainName:
		header := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}
		message.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(aliasName)}}}
	case name == aliasName:
		message.Answers = []dnsmessage.Resource{aAnswer(question.Name, chainAddress)}
	case name == truncatedName && !tcp:
		message.Truncated = true
	case name == truncatedName && tcp:
		message.Answers = []dnsmessage.Resource{aAnswer(question.Name, tcpAddress)}
	default:
		return nil, name, false, fmt.Errorf("unexpected synthetic name %q", name)
	}
	packed, err := message.Pack()
	if err != nil {
		return nil, name, message.Truncated, fmt.Errorf("pack DNS response: %w", err)
	}
	return packed, name, message.Truncated, nil
}

// aAnswer builds one fixed IN A record with a short TTL for the synthetic authority.
func aAnswer(name dnsmessage.Name, address string) dnsmessage.Resource {
	ip := net.ParseIP(address).To4()
	var octets [4]byte
	copy(octets[:], ip)
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30},
		Body:   &dnsmessage.AResource{A: octets},
	}
}

// countQuery attributes accepted requests to the fixed chain and TC scenarios.
func countQuery(network, name string, tc bool) {
	switch name {
	case chainName:
		chainQueries.Add(1)
	case aliasName:
		aliasQueries.Add(1)
	case truncatedName:
		if network == "TCP" {
			tcpFallbackQueries.Add(1)
		} else if tc {
			tcUDPQueries.Add(1)
		}
	}
}

// logCounters writes the query identity and cumulative per-transport and scenario counts.
func logCounters(network, name string, tc bool) {
	log.Printf("query transport=%s name=%s tc=%t counters udp=%d tcp=%d chain=%d alias=%d tc_udp=%d tcp_fallback=%d", network, name, tc, udpQueries.Load(), tcpQueries.Load(), chainQueries.Load(), aliasQueries.Load(), tcUDPQueries.Load(), tcpFallbackQueries.Load())
}

// runProbe resolves the CNAME chain and the independent TC fallback case through sing-box UDP DNS.
func runProbe() error {
	if err := probeChain(); err != nil {
		return err
	}
	if err := probeTCFallback(); err != nil {
		return err
	}
	log.Printf("probe success: CNAME chain and TC-to-TCP fallback validated through %s", proxyAddress)
	return nil
}

// probeChain sends one recursive query and requires both the CNAME and exact terminal A record.
func probeChain() error {
	message, err := queryUDP(chainName)
	if err != nil {
		return fmt.Errorf("CNAME chain probe: %w", err)
	}
	if len(message.Answers) < 2 {
		return fmt.Errorf("CNAME chain answer incomplete: got %d answer records", len(message.Answers))
	}
	var cnameOK, addressOK bool
	for _, answer := range message.Answers {
		switch body := answer.Body.(type) {
		case *dnsmessage.CNAMEResource:
			cnameOK = cnameOK || strings.EqualFold(body.CNAME.String(), aliasName)
		case *dnsmessage.AResource:
			addressOK = addressOK || net.IP(body.A[:]).String() == chainAddress
		}
	}
	if !message.Response || message.Truncated || message.RCode != dnsmessage.RCodeSuccess || message.Questions[0].Name.String() != chainName || !cnameOK || !addressOK {
		return fmt.Errorf("CNAME chain answer mismatch: id=%d response=%t truncated=%t rcode=%d answers=%d cname=%t A=%t", message.ID, message.Response, message.Truncated, message.RCode, len(message.Answers), cnameOK, addressOK)
	}
	log.Printf("probe pass scenario=cname-chain transport=client-udp id=%d question=%s cname=%s final_a=%s answers=%d", message.ID, chainName, aliasName, chainAddress, len(message.Answers))
	return nil
}

// probeTCFallback requires the resolver to replace a truncated UDP answer with its complete TCP retry.
func probeTCFallback() error {
	message, err := queryUDP(truncatedName)
	if err != nil {
		return fmt.Errorf("TC fallback probe: %w", err)
	}
	if !message.Response || message.Truncated || message.RCode != dnsmessage.RCodeSuccess || message.Questions[0].Name.String() != truncatedName || len(message.Answers) != 1 {
		return fmt.Errorf("TC fallback response shape mismatch: id=%d response=%t truncated=%t rcode=%d answers=%d", message.ID, message.Response, message.Truncated, message.RCode, len(message.Answers))
	}
	answer, ok := message.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || net.IP(answer.A[:]).String() != tcpAddress {
		return fmt.Errorf("TC fallback A mismatch: got=%v want=%s", message.Answers[0].Body, tcpAddress)
	}
	log.Printf("probe pass scenario=udp-tc-to-tcp id=%d question=%s final_a=%s answers=%d", message.ID, truncatedName, tcpAddress, len(message.Answers))
	return nil
}

// queryUDP sends one recursive IN A question to sing-box and validates its ID and echoed question.
func queryUDP(name string) (dnsmessage.Message, error) {
	questionName, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("encode query name: %w", err)
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: questionName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, err := query.Pack()
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("pack query: %w", err)
	}
	conn, err := net.DialTimeout("udp4", proxyAddress, 3*time.Second)
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("dial sing-box DNS inbound: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write(packet); err != nil {
		return dnsmessage.Message{}, fmt.Errorf("write DNS query: %w", err)
	}
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return dnsmessage.Message{}, fmt.Errorf("read DNS response: %w", err)
	}
	var decoded dnsmessage.Message
	if err := decoded.Unpack(response[:n]); err != nil {
		return dnsmessage.Message{}, fmt.Errorf("unpack DNS response: %w", err)
	}
	if decoded.ID != query.ID || len(decoded.Questions) != 1 || decoded.Questions[0] != query.Questions[0] {
		return dnsmessage.Message{}, errors.New("response transaction ID or question mismatch")
	}
	return decoded, nil
}
