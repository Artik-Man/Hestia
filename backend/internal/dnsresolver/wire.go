// Package dnsresolver serves client DNS through resolver/exit pairs authorized by the caller.
package dnsresolver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type question struct {
	message   dnsmessage.Message
	name      string
	keyType   dnsmessage.Type
	cacheable bool
}

// parseQuestion accepts exactly one standard question and determines whether its wire options permit shared caching.
func parseQuestion(packet []byte) (question, error) {
	var q question
	if len(packet) > 65535 {
		return q, errors.New("DNS packet too large")
	}
	if err := q.message.Unpack(packet); err != nil {
		return q, err
	}
	m := q.message
	if m.Response || m.OpCode != 0 || len(m.Questions) != 1 || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		return q, errors.New("expected one standard DNS question")
	}
	item := m.Questions[0]
	if !asciiWireName(item.Name.String()) {
		return q, errors.New("question name must use ASCII or Punycode")
	}
	q.name = strings.ToLower(strings.TrimSuffix(item.Name.String(), "."))
	q.keyType = item.Type
	plainOptions := len(m.Additionals) == 0
	if len(m.Additionals) == 1 && m.Additionals[0].Header.TTL == 0 && m.Additionals[0].Header.Name.String() == "." {
		if opt, ok := m.Additionals[0].Body.(*dnsmessage.OPTResource); ok && len(opt.Options) == 0 {
			plainOptions = true
		}
	}
	q.cacheable = item.Class == dnsmessage.ClassINET && (item.Type == dnsmessage.TypeA || item.Type == dnsmessage.TypeAAAA) && plainOptions && !m.CheckingDisabled && m.RecursionDesired && !m.AuthenticData
	return q, nil
}

// buildQuery creates a plain recursive IN question used for warming and shared client cache fills.
func buildQuery(name string, kind dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: kind, Class: dnsmessage.ClassINET}}}
	return m.Pack()
}

// failure replies to a parsed request with the original ID and question, and a resolver failure code.
func failure(q question) []byte {
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: q.message.ID, Response: true, RecursionDesired: q.message.RecursionDesired, RecursionAvailable: true, RCode: dnsmessage.RCodeServerFailure}, Questions: q.message.Questions}
	p, _ := m.Pack()
	return p
}

var errUpstreamTemporary = errors.New("upstream DNS SERVFAIL")

type outcome struct {
	packet   []byte
	positive bool
	ttl      time.Duration
	offsets  []int
}

// skipName advances past an encoded DNS name, including a terminal compression pointer.
func skipName(packet []byte, i int) (int, error) {
	for i < len(packet) {
		n := int(packet[i])
		i++
		switch {
		case n == 0:
			return i, nil
		case n&0xc0 == 0xc0 && i < len(packet):
			return i + 1, nil
		case n <= 63 && i+n <= len(packet):
			i += n
		default:
			return 0, errors.New("invalid DNS name encoding")
		}
	}
	return 0, errors.New("truncated DNS name")
}

// ttlOffsets finds TTL bytes in the original wire layout, leaving EDNS pseudo-record flags and compression intact.
func ttlOffsets(packet []byte) ([]int, error) {
	i, err := skipName(packet, 12)
	if err != nil {
		return nil, err
	}
	i += 4
	total := int(binary.BigEndian.Uint16(packet[6:8])) + int(binary.BigEndian.Uint16(packet[8:10])) + int(binary.BigEndian.Uint16(packet[10:12]))
	var offsets []int
	for range total {
		i, err = skipName(packet, i)
		if err != nil || i+10 > len(packet) {
			return nil, errors.New("truncated DNS resource")
		}
		kind := dnsmessage.Type(binary.BigEndian.Uint16(packet[i : i+2]))
		if kind != dnsmessage.TypeOPT {
			offsets = append(offsets, i+4)
		}
		start := i + 10
		i = start + int(binary.BigEndian.Uint16(packet[i+8:i+10]))
		if i > len(packet) || !resourceLengthOK(packet, kind, start, i) {
			return nil, errors.New("invalid DNS resource data length")
		}
	}
	if i != len(packet) {
		return nil, errors.New("trailing DNS response bytes")
	}
	return offsets, nil
}

// resourceLengthOK checks fixed-size addresses and name boundaries used to classify answers and negatives.
func resourceLengthOK(packet []byte, kind dnsmessage.Type, start, end int) bool {
	switch kind {
	case dnsmessage.TypeA:
		return end-start == 4
	case dnsmessage.TypeAAAA:
		return end-start == 16
	case dnsmessage.TypeCNAME, dnsmessage.TypeNS:
		i, err := skipName(packet, start)
		return err == nil && i == end
	case dnsmessage.TypeSOA:
		i, err := skipName(packet, start)
		if err != nil || i >= end {
			return false
		}
		i, err = skipName(packet, i)
		return err == nil && i+20 == end
	default:
		return true
	}
}

// asciiWireName restricts case folding to DNS ASCII, avoiding Unicode collisions in policy and cache keys.
func asciiWireName(name string) bool {
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] >= 0x7f {
			return false
		}
	}
	return true
}

// classify validates a matching transaction and separates usable answers, authoritative negatives and transient failures.
func classify(q question, id uint16, packet []byte) (outcome, error) {
	var m dnsmessage.Message
	if len(packet) > 65535 {
		return outcome{}, errors.New("oversized DNS response")
	}
	if err := m.Unpack(packet); err != nil {
		return outcome{}, err
	}
	if !m.Response || m.OpCode != 0 || m.ID != id || len(m.Questions) != 1 || m.Questions[0].Class != q.message.Questions[0].Class || m.Questions[0].Type != q.keyType || !asciiWireName(m.Questions[0].Name.String()) || !strings.EqualFold(m.Questions[0].Name.String(), q.message.Questions[0].Name.String()) {
		return outcome{}, errors.New("mismatched DNS response")
	}
	if m.Truncated {
		return outcome{}, errors.New("upstream response truncated; transport must retry over TCP")
	}
	offsets, err := ttlOffsets(packet)
	if err != nil {
		return outcome{}, err
	}
	for _, rr := range m.Additionals {
		if opt, ok := rr.Body.(*dnsmessage.OPTResource); ok {
			if rr.Header.TTL>>24 != 0 {
				return outcome{}, errors.New("extended DNS error code")
			}
			for _, option := range opt.Options {
				if option.Code == 15 {
					return outcome{}, errors.New("extended DNS error detail")
				}
			}
		}
	}
	if m.RCode == dnsmessage.RCodeServerFailure {
		return outcome{}, errUpstreamTemporary
	}
	if m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError {
		return outcome{}, fmt.Errorf("upstream DNS rcode %d", m.RCode)
	}
	positive, ttl, err := answerLifetime(q, m)
	if err != nil {
		return outcome{}, err
	}
	for _, offset := range offsets {
		ttl = min(ttl, binary.BigEndian.Uint32(packet[offset:]))
	}
	return outcome{packet: packet, positive: positive, ttl: time.Duration(ttl) * time.Second, offsets: offsets}, nil
}

// answerLifetime follows the exact CNAME chain and requires a scoped SOA or authoritative flag for negatives.
func answerLifetime(q question, m dnsmessage.Message) (bool, uint32, error) {
	owner := strings.ToLower(q.message.Questions[0].Name.String())
	class := q.message.Questions[0].Class
	aliases := make(map[string]string)
	dataAt := make(map[string]bool)
	answers := make(map[string]bool)
	const typeRRSIG dnsmessage.Type = 46
	const typeNSEC dnsmessage.Type = 47
	for _, rr := range m.Answers {
		if rr.Header.Class != class || !asciiWireName(rr.Header.Name.String()) {
			return false, 0, errors.New("unexpected DNS answer owner or class")
		}
		name := strings.ToLower(rr.Header.Name.String())
		if rr.Header.Type != dnsmessage.TypeCNAME && rr.Header.Type != typeRRSIG && rr.Header.Type != typeNSEC {
			dataAt[name] = true
		}
		if rr.Header.Type == q.keyType || q.keyType == dnsmessage.TypeALL {
			answers[name] = true
		}
		if alias, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			if !asciiWireName(alias.CNAME.String()) {
				return false, 0, errors.New("invalid CNAME target")
			}
			target := strings.ToLower(alias.CNAME.String())
			if prev, exists := aliases[name]; exists && prev != target {
				return false, 0, errors.New("ambiguous CNAME target")
			}
			aliases[name] = target
		}
	}
	for name := range aliases {
		if dataAt[name] {
			return false, 0, errors.New("record conflicts with CNAME at same owner")
		}
	}
	chain := make(map[string]bool)
	for {
		if chain[owner] {
			return false, 0, errors.New("cyclic CNAME chain")
		}
		chain[owner] = true
		if answers[owner] {
			if m.RCode != dnsmessage.RCodeSuccess {
				return false, 0, errors.New("address contradicts negative response")
			}
			return true, ^uint32(0), nil
		}
		next, ok := aliases[owner]
		if !ok {
			break
		}
		owner = next
	}
	for _, rr := range m.Answers {
		if (rr.Header.Type != dnsmessage.TypeCNAME && rr.Header.Type != typeRRSIG) || !chain[strings.ToLower(rr.Header.Name.String())] {
			return false, 0, errors.New("unrelated answer to DNS question")
		}
	}
	for _, rr := range m.Authorities {
		if soa, ok := rr.Body.(*dnsmessage.SOAResource); ok {
			zone := strings.ToLower(rr.Header.Name.String())
			if !asciiWireName(rr.Header.Name.String()) || rr.Header.Class != class || !(zone == "." || zone == owner || strings.HasSuffix(owner, "."+zone)) {
				return false, 0, errors.New("SOA does not cover negative DNS answer")
			}
			return false, min(rr.Header.TTL, soa.MinTTL), nil
		}
	}
	if !m.Authoritative || len(m.Authorities) != 0 || m.RCode == dnsmessage.RCodeSuccess && len(m.Answers) != 0 {
		return false, 0, errors.New("DNS reply lacks a final answer or authoritative negative")
	}
	return false, 0, nil
}

// randomized returns a private wire copy with an independent transaction ID for one upstream exchange.
func randomized(packet []byte) ([]byte, uint16, error) {
	copyPacket := append([]byte(nil), packet...)
	if _, err := rand.Read(copyPacket[:2]); err != nil {
		return nil, 0, err
	}
	return copyPacket, binary.BigEndian.Uint16(copyPacket[:2]), nil
}

// reply returns a response for a client transaction with TTLs aged in place in its private copy.
func (o outcome) reply(q question, age time.Duration, stale bool) []byte {
	p := append([]byte(nil), o.packet...)
	binary.BigEndian.PutUint16(p, q.message.ID)
	if stale {
		p[3] &^= 0x20
	} // Historic DNSSEC validation cannot attest to an expired answer.
	// Restore randomized client QNAME casing without moving any compression targets.
	i := 12
	for label := range strings.SplitSeq(strings.TrimSuffix(q.message.Questions[0].Name.String(), "."), ".") {
		if i >= len(p) || len(label) != int(p[i]) || i+1+len(label) > len(p) {
			break
		}
		i++
		copy(p[i:i+len(label)], label)
		i += len(label)
	}
	for _, i := range o.offsets {
		ttl := binary.BigEndian.Uint32(p[i:])
		elapsed := int64(max(age, 0) / time.Second)
		if stale || elapsed >= int64(ttl) {
			ttl = 0
		} else {
			ttl -= uint32(elapsed)
		}
		binary.BigEndian.PutUint32(p[i:], ttl)
	}
	return p
}
