//go:build keenetic

package keeneticroute

import (
	"encoding/binary"
	"testing"
)

// TestParseIngressAttributesReadsRuleSelectorsAndRejectsTruncation checks generic RPDB attribute decoding.
func TestParseIngressAttributesReadsRuleSelectorsAndRejectsTruncation(t *testing.T) {
	data := make([]byte, 12)
	data = appendNetlinkAttr(data, ingressFRAFWMARK, nativeUint32(0x0ffffabc))
	data = appendNetlinkAttr(data, ingressFRAFWMASK, nativeUint32(0xffffffff))
	data = appendNetlinkAttr(data, ingressFRAIIFName, []byte{'b', 'r', '0', 0})
	attributes, err := parseIngressAttributes(data, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 3 || attributes[0].kind != ingressFRAFWMARK || binary.NativeEndian.Uint32(attributes[0].value) != 0x0ffffabc || string(attributes[2].value) != "br0\x00" {
		t.Fatalf("unexpected parsed attributes: %#v", attributes)
	}
	if _, err := parseIngressAttributes(append(data, 1, 2), 12); err == nil {
		t.Fatal("expected truncated attribute rejection")
	}
}

// TestDecodeIngressRuleRejectsMalformedOrAmbiguousSelectors prevents incomplete kernel data from bypassing collision checks.
func TestDecodeIngressRuleRejectsMalformedOrAmbiguousSelectors(t *testing.T) {
	valid := make([]byte, 12)
	valid[0], valid[4], valid[7] = ingressIPv4Family, byte(254), byte(ingressRuleLookup)
	valid = appendNetlinkAttr(valid, ingressFRAPriority, nativeUint32(ingressRoutePriority))
	valid = appendNetlinkAttr(valid, ingressFRAFWMARK, nativeUint32(0x0ffffabc))
	valid = appendNetlinkAttr(valid, ingressFRAFWMASK, nativeUint32(0xffffffff))
	valid = appendNetlinkAttr(valid, ingressFRAIIFName, []byte{'b', 'r', '0', 0})
	valid = appendNetlinkAttr(valid, ingressFRAProtocol, []byte{2})
	valid = appendNetlinkAttr(valid, ingressFRASuppressPrefixlen, nativeUint32(0xffffffff))
	rule, err := decodeIngressRule(valid)
	if err != nil {
		t.Fatalf("decode valid rule: %v", err)
	}
	if rule.Priority != ingressRoutePriority || rule.Protocol != 2 || rule.Mark != 0x0ffffabc || rule.Mask != 0xffffffff || rule.Input != "br0" || !rule.HasMark || rule.HasOtherSelectors {
		t.Fatalf("unexpected decoded rule: %+v", rule)
	}

	malformed := make([]byte, 12)
	malformed[0] = ingressIPv4Family
	malformed = append(malformed, appendNetlinkAttr(nil, ingressFRAPriority, []byte{1, 2})...)
	if _, err := decodeIngressRule(malformed); err == nil {
		t.Fatal("malformed priority attribute was accepted")
	}
	malformedProtocol := make([]byte, 12)
	malformedProtocol[0] = ingressIPv4Family
	malformedProtocol = appendNetlinkAttr(malformedProtocol, ingressFRAProtocol, []byte{1, 2})
	if _, err := decodeIngressRule(malformedProtocol); err == nil {
		t.Fatal("malformed rule protocol metadata was accepted")
	}
	activeSuppress := make([]byte, 12)
	activeSuppress[0] = ingressIPv4Family
	activeSuppress = appendNetlinkAttr(activeSuppress, ingressFRASuppressPrefixlen, nativeUint32(0))
	rule, err = decodeIngressRule(activeSuppress)
	if err != nil || !rule.HasOtherSelectors {
		t.Fatalf("active prefix suppression must remain a foreign selector: rule=%+v err=%v", rule, err)
	}

	duplicate := append([]byte(nil), valid...)
	duplicate = append(duplicate, appendNetlinkAttr(nil, ingressFRAFWMARK, nativeUint32(0x0ffffabd))...)
	if _, err := decodeIngressRule(duplicate); err == nil {
		t.Fatal("duplicate mark selector was accepted")
	}

	badInterface := make([]byte, 12)
	badInterface[0] = ingressIPv4Family
	badInterface = appendNetlinkAttr(badInterface, ingressFRAPriority, nativeUint32(ingressRoutePriority))
	badInterface = appendNetlinkAttr(badInterface, ingressFRAIIFName, []byte{'b', 'r', '0', 0, 'x'})
	if _, err := decodeIngressRule(badInterface); err == nil {
		t.Fatal("non-canonical input interface selector was accepted")
	}
	defaultPriority := make([]byte, 12)
	defaultPriority[0], defaultPriority[7] = ingressIPv4Family, byte(ingressRuleLookup)
	rule, err = decodeIngressRule(defaultPriority)
	if err != nil || rule.Priority != 0 {
		t.Fatalf("kernel rule with omitted zero-priority attribute must decode: rule=%+v err=%v", rule, err)
	}
}

// TestRuleNetlinkPayloadUsesLinuxUnreachableAction checks the wire value independently from the model constant.
func TestRuleNetlinkPayloadUsesLinuxUnreachableAction(t *testing.T) {
	rule := ingressRule{
		Family: ingressIPv4Family, Priority: ingressBlockPriority, Mark: 0x0ffffabc,
		Mask: 0xffffffff, Action: ingressRuleUnreachable, Input: "br0", HasMark: true,
	}
	payload := ruleNetlinkPayload(rule)
	if len(payload) < 12 || payload[7] != 7 {
		t.Fatalf("unreachable RPDB action must encode FR_ACT_UNREACHABLE (7), got %d", payload[7])
	}
}
