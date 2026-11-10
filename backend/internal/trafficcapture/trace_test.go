//go:build linux && arm64 && !android && keenetic

package trafficcapture

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestValidateTraceRequest constrains trace activation to one short IPv4 TCP/UDP tuple.
func TestValidateTraceRequest(t *testing.T) {
	valid := TraceRequest{Protocol: "TCP", Source: "192.168.1.124", SourcePort: 49322, Destination: "1.1.1.1", DestinationPort: 443, DurationSeconds: 15}
	if err := ValidateTraceRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	invalid := []TraceRequest{
		{Protocol: "ICMP", Source: valid.Source, SourcePort: valid.SourcePort, Destination: valid.Destination, DestinationPort: valid.DestinationPort, DurationSeconds: 1},
		{Protocol: "TCP", Source: "2001:db8::1", SourcePort: 1, Destination: valid.Destination, DestinationPort: 443, DurationSeconds: 1},
		{Protocol: "TCP", Source: valid.Source, SourcePort: 0, Destination: valid.Destination, DestinationPort: 443, DurationSeconds: 1},
		{Protocol: "TCP", Source: valid.Source, SourcePort: 1, Destination: valid.Destination, DestinationPort: 443, DurationSeconds: 16},
	}
	for _, request := range invalid {
		if err := ValidateTraceRequest(request); err == nil {
			t.Fatalf("invalid request accepted: %+v", request)
		}
	}
}

// TestDecodeTraceRequestRejectsTrailingAndUnknownFields keeps the root command input unambiguous.
func TestDecodeTraceRequestRejectsTrailingAndUnknownFields(t *testing.T) {
	for _, input := range []string{
		`{"protocol":"TCP","source":"192.168.1.124","sourcePort":49322,"destination":"1.1.1.1","destinationPort":443,"durationSeconds":3} {}`,
		`{"protocol":"TCP","source":"192.168.1.124","sourcePort":49322,"destination":"1.1.1.1","destinationPort":443,"durationSeconds":3,"policyKey":"Policy2"}`,
		`{"protocol":"TCP","source":"192.168.1.124","sourcePort":49322,"destination":"1.1.1.1","destinationPort":443,"durationSeconds":3,"extra":true}`,
	} {
		if _, err := DecodeTraceRequest([]byte(input)); err == nil {
			t.Fatalf("invalid JSON accepted: %s", input)
		}
	}
}

// TestTupleMatcherRecognizesForwardAndReverseHeadersWithoutReadingPayload validates exact direction-specific 5-tuple matching.
func TestTupleMatcherRecognizesForwardAndReverseHeadersWithoutReadingPayload(t *testing.T) {
	request := TraceRequest{Protocol: "TCP", Source: "192.168.1.124", SourcePort: 49322, Destination: "1.1.1.1", DestinationPort: 443, DurationSeconds: 1}
	for _, iface := range []string{"br0", "opkgtun0"} {
		forward := testIPv4Header(request, iface)
		if !matchesTuple(forward, iface, request) {
			t.Fatalf("forward tuple did not match on %s", iface)
		}
		reverse := request
		reverse.Source, reverse.Destination = request.Destination, request.Source
		reverse.SourcePort, reverse.DestinationPort = request.DestinationPort, request.SourcePort
		if !matchesTuple(testIPv4Header(reverse, iface), iface, reverse) {
			t.Fatalf("reverse tuple did not match on %s", iface)
		}
		if matchesTuple(forward, iface, reverse) {
			t.Fatalf("forward tuple matched as reverse on %s", iface)
		}
		program := tupleFilter(iface, request)
		if program.Len == 0 || program.Filter == nil {
			t.Fatalf("missing kernel filter on %s", iface)
		}
	}
}

// testIPv4Header creates only synthetic base headers for tuple matcher tests.
func testIPv4Header(request TraceRequest, iface string) []byte {
	offset := 0
	if iface == "br0" {
		offset = 14
	}
	packet := make([]byte, offset+40)
	if offset > 0 {
		binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	}
	packet[offset] = 0x45
	if request.Protocol == "TCP" {
		packet[offset+9] = 6
	} else {
		packet[offset+9] = 17
	}
	source := netip.MustParseAddr(request.Source).As4()
	destination := netip.MustParseAddr(request.Destination).As4()
	copy(packet[offset+12:offset+16], source[:])
	copy(packet[offset+16:offset+20], destination[:])
	binary.BigEndian.PutUint16(packet[offset+20:offset+22], uint16(request.SourcePort))
	binary.BigEndian.PutUint16(packet[offset+22:offset+24], uint16(request.DestinationPort))
	return packet
}
