package binding

import (
	"errors"
	"testing"
)

// TestIncludeRuntimeChangeRetriesAnUnchangedAWG verifies explicit profile saves restart an unchanged ready connector.
func TestIncludeRuntimeChangeRetriesAnUnchangedAWG(t *testing.T) {
	ready := map[string]runtimeGeneration{"vpn": {slot: 2}}
	var plan runtimePlan
	if err := includeRuntimeChange(&plan, ready, "vpn"); err != nil {
		t.Fatalf("includeRuntimeChange() error = %v", err)
	}
	if len(plan.changes) != 1 || plan.changes[0] != (runtimeChange{id: "vpn", slot: 2}) {
		t.Fatalf("includeRuntimeChange() plan = %+v, want one restart for vpn", plan)
	}
	if err := includeRuntimeChange(&plan, ready, "vpn"); err != nil || len(plan.changes) != 1 {
		t.Fatalf("includeRuntimeChange() duplicated a restart: plan=%+v err=%v", plan, err)
	}
}

// TestIncludeRuntimeChangeRejectsUnknownAWG verifies an explicit retry cannot name a connector absent from the ready generation.
func TestIncludeRuntimeChangeRejectsUnknownAWG(t *testing.T) {
	var plan runtimePlan
	if err := includeRuntimeChange(&plan, nil, "missing"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("includeRuntimeChange() error = %v, want ErrUnavailable", err)
	}
	if len(plan.changes) != 0 {
		t.Fatalf("includeRuntimeChange() changed plan for unknown connector: %+v", plan)
	}
}
