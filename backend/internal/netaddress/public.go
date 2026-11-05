// Package netaddress validates Internet destinations for probes and external lookups.
package netaddress

import "net/netip"

// These special-purpose ranges can pass IsGlobalUnicast yet designate private overlays,
// documentation, benchmarking, transition mechanisms, or reserved address space.
var excludedTargets = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var publicIPv6 = netip.MustParsePrefix("2000::/3")

// Public reports whether an address is publicly routable, excluding special-purpose and transition ranges.
func Public(ip netip.Addr) bool {
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !publicIPv6.Contains(ip)) {
		return false
	}
	for _, prefix := range excludedTargets {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
