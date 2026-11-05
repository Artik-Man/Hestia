//go:build linux

package quality

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"
)

// TestRawEchoLoopback verifies Linux raw IPv4 header removal and IPv6 echo checksums on the selected interface.
func TestRawEchoLoopback(t *testing.T) {
	for _, family := range []struct{ network, target string }{{"ip4:icmp", "127.0.0.1"}, {"ip6:ipv6-icmp", "::1"}} {
		t.Run(family.network, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			path := Path{Device: "lo"}
			conn, err := path.dial(ctx, family.network, family.target)
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.ENETUNREACH) {
				t.Skipf("raw loopback unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			conn.Close()
			if got := probeICMP(ctx, path, family.target); got != success {
				t.Fatalf("connected raw socket probe to %s returned %v", family.target, got)
			}
		})
	}
}
