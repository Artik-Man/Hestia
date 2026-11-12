//go:build keenetic

package entware

import "testing"

// TestHasManagedIngressRequiresExactNoAutoRouteTUN verifies route activation rejects incompatible or ambiguous inbounds.
func TestHasManagedIngressRequiresExactNoAutoRouteTUN(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "managed inbound",
			data: `{"inbounds":[{"type":"tun","tag":"hestia-keenetic-ingress","interface_name":"opkgtun0","address":["172.31.250.2/30"],"auto_route":false}]}`,
			want: true,
		},
		{
			name: "auto route enabled",
			data: `{"inbounds":[{"type":"tun","tag":"hestia-keenetic-ingress","interface_name":"opkgtun0","address":["172.31.250.2/30"],"auto_route":true}]}`,
		},
		{
			name: "wrong interface",
			data: `{"inbounds":[{"type":"tun","tag":"hestia-keenetic-ingress","interface_name":"opkgtun1","address":["172.31.250.2/30"],"auto_route":false}]}`,
		},
		{
			name: "duplicate tag",
			data: `{"inbounds":[{"type":"tun","tag":"hestia-keenetic-ingress","interface_name":"opkgtun0","address":["172.31.250.2/30"],"auto_route":false},{"type":"tun","tag":"hestia-keenetic-ingress","interface_name":"opkgtun0","address":["172.31.250.2/30"],"auto_route":false}]}`,
		},
		{
			name: "invalid json",
			data: `{"inbounds":[`,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := hasManagedIngress([]byte(test.data)); got != test.want {
				t.Fatalf("hasManagedIngress() = %t, want %t", got, test.want)
			}
		})
	}
}
