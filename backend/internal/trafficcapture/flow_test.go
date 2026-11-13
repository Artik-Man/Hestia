package trafficcapture

import (
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
)

// TestFlowEvidence preserves client flows, distinguishes route decisions from delivery and drops internal probes.
func TestFlowEvidence(t *testing.T) {
	var events []traffic.TrafficEvent
	p := newParser(func(e traffic.TrafficEvent) { events = append(events, e) })
	now := time.Now()
	for _, message := range []string{
		"[12 0ms] inbound/socks[_quality-fi]: inbound connection to 127.0.0.1:80",
		"[12 0ms] outbound/direct[fi]: outbound connection to 127.0.0.1:80",
		"[13 1ms] inbound/tun[lan]: inbound packet connection to [2001:db8::2]:443",
		"[13 1ms] router: match[2] ip_cidr=2001:db8::/32 => route(fi-group)",
		"[13 2ms] outbound/direct[fi]: outbound packet connection",
		"[14 0ms] inbound/socks[client]: inbound connection to example.org:443",
		"[14 1ms] router: match[0] domain=example.org => reject",
		"[15 0ms] inbound/tun[lan]: inbound connection to 198.18.0.3:443",
		"[15 0ms] router: found fakeip domain: cache.example",
		"[15 1ms] outbound/direct[fi]: outbound connection to cache.example:443",
		"[16 0ms] inbound/tun[lan]: inbound packet connection to 192.0.2.1:53",
		"[16 0ms] router: match[0] inbound=lan => hijack-dns",
		"[17 0ms] inbound/tun[lan]: inbound connection to 203.0.113.1:443",
	} {
		p.accept(now, message)
	}
	p.flushBefore(now)
	if len(events) != 4 {
		t.Fatalf("events: %+v", events)
	}
	if e := events[0]; e.Address != "2001:db8::2" || e.Port != 443 || e.Protocol != "UDP" || e.Group != "fi-group" || e.Connection != "fi" || e.Kind != traffic.Unconfirmed || e.NetworkInterface != "" {
		t.Fatalf("UDP evidence: %+v", e)
	}
	if e := events[1]; e.Domain != "example.org" || e.Address != "" || e.Kind != traffic.Blocked || e.BlockReason == "" || e.Connection != "" {
		t.Fatalf("reject: %+v", e)
	}
	if e := events[2]; e.Domain != "cache.example" || e.FakeIP != "198.18.0.3" || e.Address != "" {
		t.Fatalf("FakeIP: %+v", e)
	}
	if e := events[3]; e.Address != "203.0.113.1" || e.Connection != "" || e.Kind != traffic.Unconfirmed {
		t.Fatalf("incomplete: %+v", e)
	}
}

// TestRouteFormats recognizes explicit block connectors, a single resolved address, and TUN packet-mode events.
func TestRouteFormats(t *testing.T) {
	var events []traffic.TrafficEvent
	p := newParser(func(e traffic.TrafficEvent) { events = append(events, e) })
	now := time.Now()
	for _, line := range []string{
		"[1 0ms] inbound/socks[0]: inbound connection to single.example:443",
		"[1 0ms] router: resolved [192.0.2.1]",
		"[1 1ms] outbound/direct[wan]: outbound connection to single.example:443",
		"[2 0ms] inbound/socks[0]: inbound connection to multi.example:443",
		"[2 0ms] router: resolved [192.0.2.1 192.0.2.2]",
		"[2 1ms] outbound/block[closed-link]: blocked connection to multi.example:443",
		"[3 1ms] router: pre-match: forward udp connection from 10.0.0.5 to 2001:db8::3 via outbound/wireguard[12345678-1234-4567-890a-123456789abc]",
		"[4 0ms] inbound/socks[0]: inbound connection to 192.0.2.2:443",
		"[4 0ms] router: sniffed protocol: tls, domain: host.example, client: chrome",
		"[4 1ms] outbound/direct[wan]: outbound connection to 192.0.2.2:443",
	} {
		p.accept(now, line)
	}
	if len(events) != 4 {
		t.Fatalf("events: %+v", events)
	}
	if events[0].Address != "192.0.2.1" || events[0].Kind != traffic.Unconfirmed {
		t.Fatalf("single target: %+v", events[0])
	}
	if events[1].Address != "" || events[1].Kind != traffic.Blocked || events[1].Connection != "" {
		t.Fatalf("blocked: %+v", events[1])
	}
	if events[2].Port != 0 || events[2].Connection != "12345678-1234-4567-890a-123456789abc" || events[2].Protocol != "UDP" || events[2].Address != "2001:db8::3" {
		t.Fatalf("fast path: %+v", events[2])
	}
	if events[3].Domain != "host.example" || events[3].Address != "192.0.2.2" {
		t.Fatalf("sniff: %+v", events[3])
	}
}

// TestQUICEvidence classifies only a pending UDP flow with exact same-context QUIC sniff evidence.
func TestQUICEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, ingress, sniff, wantProtocol, wantDomain string
	}{
		{"domain", "packet ", "[1 0ms] router: sniffed packet protocol: quic, domain: video.example, client: chrome", "QUIC", "video.example"},
		{"without domain", "packet ", "[1 0ms] router: sniffed packet protocol: quic", "QUIC", ""},
		{"ordinary UDP443", "packet ", "", "UDP", ""},
		{"foreign context", "packet ", "[2 0ms] router: sniffed packet protocol: quic", "UDP", ""},
		{"TCP", "", "[1 0ms] router: sniffed packet protocol: quic", "TCP", ""},
		{"different token", "packet ", "[1 0ms] router: sniffed packet protocol: quic-fake", "UDP", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []traffic.TrafficEvent
			p := newParser(func(e traffic.TrafficEvent) { events = append(events, e) })
			now := time.Now()
			p.accept(now, "[1 0ms] inbound/tun[lan]: inbound "+tc.ingress+"connection to 192.0.2.2:443")
			p.accept(now, tc.sniff)
			p.accept(now, "[1 1ms] outbound/direct[wan]: outbound "+tc.ingress+"connection to 192.0.2.2:443")
			if len(events) != 1 || events[0].Protocol != tc.wantProtocol || events[0].Domain != tc.wantDomain {
				t.Fatalf("events: %+v", events)
			}
		})
	}
}
