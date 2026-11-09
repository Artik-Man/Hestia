package keeneticrci

import (
	"encoding/json"
	"testing"
)

// TestJoinIPPoliciesCombinesRuntimeIdentityAndEnabledOpkgTun verifies the RCI records join without retaining descriptions.
func TestJoinIPPoliciesCombinesRuntimeIdentityAndEnabledOpkgTun(t *testing.T) {
	config := json.RawMessage(`{"Policy1":{"description":"test policy","permit":[{"interface":"OpkgTun0","enabled":true},{"interface":"eth3","enabled":false},{"interface":"","enabled":false}]},"Policy0":{"description":"other policy","permit":[{"interface":"OpkgTun1","enabled":false},{"interface":"","enabled":false}]}}`)
	runtime := json.RawMessage(`{"Policy0":{"description":"other policy","table4":4102,"table6":0,"mark":"ffffaad"},"Policy1":{"description":"test policy","table4":4104,"table6":0,"mark":"0xffffab0"}}`)
	policies, err := joinIPPolicies(config, runtime)
	if err != nil {
		t.Fatalf("join policies: %v", err)
	}
	if len(policies) != 2 || policies[0].Key != "Policy0" || policies[1].Key != "Policy1" {
		t.Fatalf("policy order or count differs: %+v", policies)
	}
	if policies[0].Table4 != 4102 || policies[0].Mark4 != 0x0ffffaad || len(policies[0].OpkgTunInterfaces) != 0 {
		t.Fatalf("unexpected first policy identity: %+v", policies[0])
	}
	if policies[1].Table4 != 4104 || policies[1].Mark4 != 0x0ffffab0 || len(policies[1].OpkgTunInterfaces) != 1 {
		t.Fatalf("unexpected OpkgTun policy identity: %+v", policies[1])
	}
	if len(policies[1].OpkgTunInterfaces) != 1 || policies[1].OpkgTunInterfaces[0] != "OpkgTun0" {
		t.Fatalf("unexpected permitted OpkgTun list: %+v", policies[1].OpkgTunInterfaces)
	}
}

// TestJoinIPPoliciesRejectsMismatchedRuntimeKeys prevents use of a table or mark from another policy record.
func TestJoinIPPoliciesRejectsMismatchedRuntimeKeys(t *testing.T) {
	config := json.RawMessage(`{"Policy0":{"permit":[{"interface":"OpkgTun0","enabled":true}]}}`)
	runtime := json.RawMessage(`{"Policy1":{"table4":4104,"mark":"ffffab0"}}`)
	if _, err := joinIPPolicies(config, runtime); err == nil {
		t.Fatal("mismatched policy config/runtime records were accepted")
	}
}

// TestParsePolicyMarkRestrictsObservedKeeneticRange rejects malformed and out-of-range marks.
func TestParsePolicyMarkRestrictsObservedKeeneticRange(t *testing.T) {
	for _, value := range []string{"", "0x202", "10000000", "100000000", "not-a-mark"} {
		if _, err := parsePolicyMark(value); err == nil {
			t.Fatalf("unsafe policy mark %q was accepted", value)
		}
	}
}

// TestJoinIPPoliciesRejectsDuplicateRouteIdentities prevents two policies from sharing a selector or FIB table.
func TestJoinIPPoliciesRejectsDuplicateRouteIdentities(t *testing.T) {
	config := json.RawMessage(`{"Policy0":{"permit":[]},"Policy1":{"permit":[]}}`)
	runtime := json.RawMessage(`{"Policy0":{"table4":4102,"mark":"ffffaaa"},"Policy1":{"table4":4102,"mark":"ffffaab"}}`)
	if _, err := joinIPPolicies(config, runtime); err == nil {
		t.Fatal("expected duplicate policy table rejection")
	}
	runtime = json.RawMessage(`{"Policy0":{"table4":4102,"mark":"ffffaaa"},"Policy1":{"table4":4103,"mark":"ffffaaa"}}`)
	if _, err := joinIPPolicies(config, runtime); err == nil {
		t.Fatal("expected duplicate policy mark rejection")
	}
}
