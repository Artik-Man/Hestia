//go:build linux

package awg

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/awgruntime"
)

// TestClassifyHealthProbeErrorReturnsSafeCategories distinguishes tunnel DNS and HTTPS failures without exposing endpoint data.
func TestClassifyHealthProbeErrorReturnsSafeCategories(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{name: "dns", err: errors.New("AWG-bound DNS probe failed"), want: "AWG runtime health probe failed: DNS"},
		{name: "https", err: errors.New("AWG-bound HTTPS probe failed"), want: "AWG runtime health probe failed: HTTPS"},
		{name: "status", err: errors.New("AWG-bound HTTPS probe returned an unexpected status"), want: "AWG runtime health probe failed: HTTPS status"},
		{name: "unknown", err: errors.New("private network detail"), want: "AWG runtime health probe failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyHealthProbeError(test.err); got == nil || got.Error() != test.want {
				t.Fatalf("classifyHealthProbeError() = %v, want %q", got, test.want)
			}
		})
	}
}

// TestProfileDNSIPv4PreservesConfiguredResolvers selects unique IPv4 resolvers in profile order without exposing the profile.
func TestProfileDNSIPv4PreservesConfiguredResolvers(t *testing.T) {
	got := profileDNSIPv4([]netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("1.0.0.1"),
		netip.MustParseAddr("1.1.1.1"),
	})
	want := []string{"1.1.1.1", "1.0.0.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("profileDNSIPv4() = %v, want %v", got, want)
	}
}

// TestClassifyHandshakeFreshnessReducesPeerStateToSafeCategories checks that handshake timestamps become coarse health labels.
func TestClassifyHandshakeFreshnessReducesPeerStateToSafeCategories(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{name: "recent", data: "peer-secret 1799999990\n", want: "recent"},
		{name: "stale", data: "peer-secret 1799999000\n", want: "stale"},
		{name: "missing", data: "peer-secret 0\n", want: "missing"},
		{name: "malformed", data: "private-output\n", want: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyHandshakeFreshness([]byte(test.data), now); got != test.want {
				t.Fatalf("classifyHandshakeFreshness() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestClassifyTransferChangeDiscardsPeerIdentifiersAndExactVolumes compares counters without returning either value.
func TestClassifyTransferChangeDiscardsPeerIdentifiersAndExactVolumes(t *testing.T) {
	for _, test := range []struct {
		name   string
		before string
		after  string
		want   string
	}{
		{name: "rx-changed", before: "peer-a 10 20\n", after: "peer-a 11 20\n", want: "rx-changed"},
		{name: "tx-changed", before: "peer-a 10 20\n", after: "peer-a 10 21\n", want: "tx-changed"},
		{name: "both-changed", before: "peer-a 10 20\n", after: "peer-a 11 21\n", want: "rx-tx-changed"},
		{name: "unchanged", before: "peer-a 10 20\n", after: "peer-a 10 20\n", want: "unchanged"},
		{name: "invalid", before: "peer-a 10 20\n", after: "private-output\n", want: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := classifyTransferChange([]byte(test.before), []byte(test.after)); got != test.want {
				t.Fatalf("classifyTransferChange() = %q, want %q", got, test.want)
			}
		})
	}
}

// TestClassifyHealthProbeFailureReportsOnlySafeCategories verifies failure logs omit peer identifiers and byte counts.
func TestClassifyHealthProbeFailureReportsOnlySafeCategories(t *testing.T) {
	responses := map[awgruntime.Query][]byte{
		awgruntime.LatestHandshakes: []byte("private-peer " + strconv.FormatInt(time.Now().Unix(), 10) + "\n"),
		awgruntime.Transfer:         []byte("private-peer 19 23\n"),
	}
	reader := func(query awgruntime.Query, _ string) ([]byte, error) { return responses[query], nil }
	err := classifyHealthProbeFailure(errors.New("AWG-bound DNS probe failed"), nil, reader, "awg0", []byte("private-peer 19 22\n"))
	if got, want := err.Error(), "AWG runtime health probe failed: DNS (handshake=recent, transfer=tx-changed, separate-https=passed)"; got != want {
		t.Fatalf("classifyHealthProbeFailure() = %q, want %q", got, want)
	}
}

type keepaliveCall struct {
	name  string
	peer  string
	value string
	ctx   context.Context
	err   error
}

// Keepalive records one bounded peer update for restoreKeepalive tests.
func (c *keepaliveCall) Keepalive(ctx context.Context, name, peer, value string) error {
	c.name, c.peer, c.value, c.ctx = name, peer, value, ctx
	return c.err
}

// TestRestoreKeepaliveUsesIndependentDeadline verifies restore does not inherit an expired handshake deadline.
func TestRestoreKeepaliveUsesIndependentDeadline(t *testing.T) {
	config := []byte("[Peer]\nPublicKey = peer-key\nPersistentKeepalive = 25\n")
	call := &keepaliveCall{}
	if err := restoreKeepalive("awg0", "peer-key", config, call); err != nil {
		t.Fatalf("restoreKeepalive() error = %v", err)
	}
	if call.name != "awg0" || call.peer != "peer-key" || call.value != "25" {
		t.Fatalf("Keepalive() = (%q, %q, %q), want (awg0, peer-key, 25)", call.name, call.peer, call.value)
	}
	deadline, ok := call.ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
		t.Fatalf("restore context deadline = %v, want a future deadline within 10 seconds", deadline)
	}
}

// TestRestoreKeepaliveUsesZeroWhenTheProfileOmitsIt verifies a temporary probe keepalive is removed afterward.
func TestRestoreKeepaliveUsesZeroWhenTheProfileOmitsIt(t *testing.T) {
	call := &keepaliveCall{}
	if err := restoreKeepalive("awg0", "peer-key", []byte("[Peer]\nPublicKey = peer-key\n"), call); err != nil {
		t.Fatalf("restoreKeepalive() error = %v", err)
	}
	if call.value != "0" {
		t.Fatalf("Keepalive() value = %q, want 0", call.value)
	}
}

// TestRestoreKeepaliveReturnsSanitizedError verifies runtime failures do not expose command output.
func TestRestoreKeepaliveReturnsSanitizedError(t *testing.T) {
	call := &keepaliveCall{err: errors.New("private runtime output")}
	if err := restoreKeepalive("awg0", "peer-key", []byte("[Peer]\nPublicKey = peer-key\n"), call); err == nil || err.Error() != "cannot restore AWG peer keepalive" {
		t.Fatalf("restoreKeepalive() error = %v, want sanitized runtime error", err)
	}
}

// TestClassifyKeepaliveRestoreErrorReportsDeadline verifies only timeout category is added to diagnostics.
func TestClassifyKeepaliveRestoreErrorReportsDeadline(t *testing.T) {
	if err := classifyKeepaliveRestoreError(context.DeadlineExceeded); err == nil || err.Error() != "cannot restore AWG peer keepalive before timeout" {
		t.Fatalf("classifyKeepaliveRestoreError() = %v, want timeout category", err)
	}
}

// TestClassifyKeepaliveRestoreErrorReportsEntwareFailure verifies a tool exit is separated from a timeout.
func TestClassifyKeepaliveRestoreErrorReportsEntwareFailure(t *testing.T) {
	if err := classifyKeepaliveRestoreError(awgruntime.ErrCommandFailed); err == nil || err.Error() != "cannot restore AWG peer keepalive: Entware awg command failed" {
		t.Fatalf("classifyKeepaliveRestoreError() = %v, want Entware command category", err)
	}
}

// TestClassifyKeepaliveRestoreErrorReportsInvalidRequest verifies invalid command arguments are diagnosed without values.
func TestClassifyKeepaliveRestoreErrorReportsInvalidRequest(t *testing.T) {
	if err := classifyKeepaliveRestoreError(awgruntime.ErrInvalidKeepaliveRequest); err == nil || err.Error() != "cannot restore AWG peer keepalive: invalid Entware request" {
		t.Fatalf("classifyKeepaliveRestoreError() = %v, want invalid request category", err)
	}
}
