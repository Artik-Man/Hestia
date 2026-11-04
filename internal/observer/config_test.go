package observer

import (
	"fmt"
	"testing"
	"time"
)

// TestDecodeBounds restricts probe cardinality and time budgets independently of Linux network access.
func TestDecodeBounds(t *testing.T) {
	const form = `{"group":"FI","connections":[{"id":"FI1","interface":"fi1"}],"targets":[{"address":"%s","protocol":"%s","port":53}],"interval":"%s","timeout":"%s","window":"%s","min_samples":1}`
	for _, tc := range []struct {
		name, address, protocol, interval, timeout, window string
		valid                                              bool
	}{
		{"valid", "203.0.113.77", "udp", "1s", "100ms", "1h", true},
		{"hostname", "vpn.example", "udp", "1s", "100ms", "1h", false},
		{"multicast", "224.0.0.1", "udp", "1s", "100ms", "1h", false},
		{"unsupported protocol", "203.0.113.77", "sctp", "1s", "100ms", "1h", false},
		{"overlapping budget", "203.0.113.77", "udp", "1s", "2s", "1h", false},
		{"unbounded window", "203.0.113.77", "udp", "20ms", "20ms", "100h", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode([]byte(fmt.Sprintf(form, tc.address, tc.protocol, tc.interval, tc.timeout, tc.window)))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

// TestDefaults verifies the agreed hour window and rejects an explicitly negative programmatic timeout.
func TestDefaults(t *testing.T) {
	cfg, err := Decode([]byte(`{"group":"FI","connections":[{"id":"fi1","interface":"eth0"}],"targets":[{"address":"203.0.113.77","protocol":"tcp","port":443}]}`))
	if err != nil || cfg.Window != time.Hour {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg.Timeout = -time.Second
	if cfg.validate() == nil {
		t.Fatal("negative timeout accepted")
	}
}
