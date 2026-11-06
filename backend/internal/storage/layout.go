// Package storage defines installed resources and filesystem mechanisms for platform adapters.
package storage

// Layout names installed resources without exposing a platform directory convention to consumers.
type Layout struct {
	Config, Snapshot, BackendConfig, InstallLock, BindingMarker      string
	AWGStore, AWGRuntime, AWGReady, AWGHealth, AWGRoutes             string
	CountryPolicy, QualitySettings, QualityRuntime, QualityReport    string
	DNSPaths, DNSPolicy, DNSCache, DNSReport                         string
	Traffic, GeoIPProposals, GeoIPIndex, NetworkProfiles, ResolvConf string
}

// Linux returns the existing standalone Linux installation layout as an independent value.
func Linux() Layout {
	return Layout{
		Config: "/etc/hestia", Snapshot: "/etc/hestia/snapshot.json", BackendConfig: "/etc/hestia/sing-box.json",
		InstallLock: "/run/hestia-install.lock", BindingMarker: "/etc/tmpfiles.d/hestia-binding.conf",
		AWGStore: "/etc/hestia/awg", AWGRuntime: "/run/hestia-awg", AWGReady: "/run/hestia-awg/ready", AWGHealth: "/run/hestia-awg/health.json", AWGRoutes: "/run/hestia-awg/routes.json",
		CountryPolicy: "/var/lib/hestia-country-map/policy.json", QualitySettings: "/var/lib/hestia-quality-settings/settings.json", QualityRuntime: "/run/hestia-quality", QualityReport: "/run/hestia-quality/report.json",
		DNSPaths: "/run/hestia-dns/paths.json", DNSPolicy: "/var/lib/hestia-dns-policy/policy.json", DNSCache: "/var/lib/hestia-dns/cache.json", DNSReport: "/run/hestia-dns/report.json",
		Traffic: "/var/lib/hestia-traffic", GeoIPProposals: "/var/lib/hestia-geoip-proposals", GeoIPIndex: "/usr/share/hestia/geoip/country.bin", NetworkProfiles: "/etc/NetworkManager/system-connections", ResolvConf: "/etc/resolv.conf",
	}
}
