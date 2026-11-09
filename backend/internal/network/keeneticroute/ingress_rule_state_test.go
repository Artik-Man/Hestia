//go:build keenetic

package keeneticroute

import (
	"bytes"
	"testing"
)

// TestIngressRuleRegistryRoundTripKeepsCanonicalIdentities verifies stable ordering and exclusion of runtime ownership flags.
func TestIngressRuleRegistryRoundTripKeepsCanonicalIdentities(t *testing.T) {
	lookup := ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Table: 30001, Action: ingressRuleLookup, Input: "br0", HasMark: true}
	block := ingressRule{Family: ingressIPv6Family, Priority: ingressRoutePriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Action: ingressRuleUnreachable, Input: "br0", HasMark: true}
	lookup.Owned = true
	encoded, err := encodeIngressRuleRegistry([]ingressRule{block, lookup})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("Owned")) {
		t.Fatalf("runtime ownership flag leaked into persisted identity: %s", encoded)
	}
	decoded, err := parseIngressRuleRegistry(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Family != ingressIPv4Family || decoded[1].Family != ingressIPv6Family ||
		decoded[0].Owned || decoded[1].Owned || !sameIngressRuleIdentity(decoded[0], lookup) || !sameIngressRuleIdentity(decoded[1], block) {
		t.Fatalf("ownership identities did not round-trip canonically: %#v", decoded)
	}
	encodedAgain, err := encodeIngressRuleRegistry(decoded)
	if err != nil || !bytes.Equal(encoded, encodedAgain) {
		t.Fatalf("registry encoding is not stable: first=%s second=%s err=%v", encoded, encodedAgain, err)
	}
}

// TestIngressRuleRegistryRejectsMalformedRecords rejects noncanonical bytes, unsupported selectors, duplicates, and extra data.
func TestIngressRuleRegistryRejectsMalformedRecords(t *testing.T) {
	rule := ingressRule{Family: ingressIPv4Family, Priority: ingressRoutePriority, Mark: 0x0ffffabc, Mask: 0xffffffff, Table: 30001, Action: ingressRuleLookup, Input: "br0", HasMark: true}
	canonical, err := encodeIngressRuleRegistry([]ingressRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := encodeIngressRuleRegistry([]ingressRule{rule, rule})
	if err == nil || duplicate != nil {
		t.Fatalf("duplicate identities were encoded: data=%q err=%v", duplicate, err)
	}
	for name, input := range map[string][]byte{
		"empty":              nil,
		"missing newline":    bytes.TrimSuffix(canonical, []byte("\n")),
		"trailing json":      append(append([]byte(nil), canonical...), []byte("{}\n")...),
		"unknown field":      []byte(`{"version":1,"rules":[],"other":1}` + "\n"),
		"unsupported family": []byte(`{"version":1,"rules":[{"Family":99,"Priority":7,"Protocol":0,"Mark":268434108,"Mask":4294967295,"Table":30001,"Action":1,"Input":"br0","SourcePrefixBits":0,"DestPrefixBits":0,"TOS":0,"Flags":0,"HasOtherSelectors":false,"HasMark":true}]}` + "\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseIngressRuleRegistry(input); err == nil {
				t.Fatalf("malformed record was accepted: %q", input)
			}
		})
	}
}
