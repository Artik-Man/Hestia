//go:build linux

package entware

import (
	"testing"

	"github.com/Artik-Man/Hestia/internal/routing"
)

// TestEffectiveHealthRequiresFreshAWGHeartbeat keeps configured AWG exits unavailable until their runtime heartbeat is fresh.
func TestEffectiveHealthRequiresFreshAWGHeartbeat(t *testing.T) {
	config := smokeConfig{
		Groups:         []routing.Group{{ID: "amnezia", Exits: []string{"awg-connector"}}},
		Healthy:        map[string]bool{"awg-connector": true},
		ConnectorKinds: map[string]string{"awg-connector": "awg"},
	}
	for _, tc := range []struct {
		name  string
		ready func(string) bool
		want  bool
	}{
		{name: "stale heartbeat", ready: func(string) bool { return false }, want: false},
		{name: "fresh heartbeat", ready: func(string) bool { return true }, want: true},
		{name: "missing heartbeat reader", ready: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			health := effectiveHealth(config, backendConfig{}, tc.ready)
			if health["awg-connector"] != tc.want {
				t.Fatalf("AWG health = %v, want %v", health["awg-connector"], tc.want)
			}
		})
	}
}
