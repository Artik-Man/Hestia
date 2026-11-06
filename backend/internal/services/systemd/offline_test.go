package systemd

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
)

// TestRetirementRequiresBothConfirmedStates keeps failures and transitional states fail closed.
func TestRetirementRequiresBothConfirmedStates(t *testing.T) {
	for _, state := range []string{"active", "activating", "deactivating", "unknown", ""} {
		v := OfflineVerifier{Output: func(context.Context, string, ...string) ([]byte, error) { return []byte(state), nil }}
		if v.RetirementOffline(context.Background(), "fi-1", false) == nil {
			t.Fatalf("accepted %q", state)
		}
	}
	var units []string
	v := OfflineVerifier{Output: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "/usr/bin/systemctl" || !reflect.DeepEqual(args[:3], []string{"show", "--property=ActiveState", "--value"}) {
			t.Fatal("wrong command")
		}
		units = append(units, args[3])
		return []byte("failed\n"), nil
	}}
	if err := v.RetirementOffline(context.Background(), "fi-1", false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(units, []string{"hestia-sing-box.service", "hestia-awg@fi-1.service"}) {
		t.Fatal(units)
	}
	v.Output = func(context.Context, string, ...string) ([]byte, error) {
		return []byte("inactive"), errors.New("unreadable")
	}
	if v.RetirementOffline(context.Background(), "fi-1", true) == nil {
		t.Fatal("accepted read failure")
	}
}

// TestOutboundDoesNotAcceptGenericFailure proves unavailable systemctl never permits guard teardown.
func TestOutboundDoesNotAcceptGenericFailure(t *testing.T) {
	for _, failure := range []error{nil, context.Canceled, errors.New("missing binary"), &exec.ExitError{}} {
		v := OfflineVerifier{Run: func(context.Context, string, ...string) error { return failure }}
		if v.OutboundDisabled(context.Background()) == nil {
			t.Fatalf("accepted %v", failure)
		}
	}
}

// TestOutboundAcceptsOnlyExitThree preserves the historical successful stop proof and rejects other statuses.
func TestOutboundAcceptsOnlyExitThree(t *testing.T) {
	for _, code := range []string{"1", "3", "4"} {
		failure := exec.Command("/bin/sh", "-c", "exit "+code).Run()
		v := OfflineVerifier{Run: func(context.Context, string, ...string) error { return failure }}
		err := v.OutboundDisabled(context.Background())
		if (err == nil) != (code == "3") {
			t.Fatalf("exit %s: %v", code, err)
		}
	}
}
