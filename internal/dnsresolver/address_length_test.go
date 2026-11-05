package dnsresolver

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// TestAddressLengthRejectsMalformedReply verifies that invalid on-wire address lengths cannot produce a usable cached answer.
func TestAddressLengthRejectsMalformedReply(t *testing.T) {
	for _, tc := range []struct {
		kind  dnsmessage.Type
		width int
	}{{dnsmessage.TypeA, 4}, {dnsmessage.TypeAAAA, 16}} {
		wire, err := buildQuery("length.example", tc.kind)
		if err != nil {
			t.Fatal(err)
		}
		q, err := parseQuestion(wire)
		if err != nil {
			t.Fatal(err)
		}
		valid, err := fixtureAnswer(wire, dnsmessage.RCodeSuccess, 300, 9)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := classify(q, q.message.ID, valid); err != nil {
			t.Fatalf("valid address rejected: %v", err)
		}
		wrong := append(append([]byte(nil), valid...), 0)
		widthOffset := len(valid) - tc.width - 2
		binary.BigEndian.PutUint16(wrong[widthOffset:], uint16(tc.width+1))
		if result, err := classify(q, q.message.ID, wrong); err == nil {
			t.Fatalf("invalid %s RDLENGTH %d accepted (positive=%t)", tc.kind, tc.width+1, result.positive)
		}
	}
}
