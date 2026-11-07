// Package storage defines installed resources and filesystem mechanisms for platform adapters.
package storage

// Layout names installed resources without exposing a platform directory convention to consumers.
type Layout struct {
	Config, Snapshot, BackendConfig, InstallLock, BindingMarker      string
	Runtime, ServicesSocket                                          string
	PanelListen, PanelAssets                                         string
	AWGStore, AWGRuntime, AWGReady, AWGHealth, AWGRoutes             string
	CountryPolicy, QualitySettings, QualityRuntime, QualityReport    string
	DNSConfig, DNSPaths, DNSPolicy, DNSCache, DNSReport              string
	Traffic, GeoIPProposals, GeoIPIndex, NetworkProfiles, ResolvConf string
}

// Linux returns the existing standalone Linux installation layout as an independent value.
func Linux() Layout {
	return Layout{
		Config: "/etc/hestia", Snapshot: "/etc/hestia/snapshot.json", BackendConfig: "/etc/hestia/sing-box.json",
		Runtime: "/run/hestia", ServicesSocket: "/run/hestia/services.sock",
		PanelListen: "/etc/hestia/panel-listen", PanelAssets: "/usr/local/share/hestia-panel/current",
		InstallLock: "/run/hestia-install.lock", BindingMarker: "/etc/tmpfiles.d/hestia-binding.conf",
		AWGStore: "/etc/hestia/awg", AWGRuntime: "/run/hestia-awg", AWGReady: "/run/hestia-awg/ready", AWGHealth: "/run/hestia-awg/health.json", AWGRoutes: "/run/hestia-awg/routes.json",
		CountryPolicy: "/var/lib/hestia-country-map/policy.json", QualitySettings: "/var/lib/hestia-quality-settings/settings.json", QualityRuntime: "/run/hestia-quality", QualityReport: "/run/hestia-quality/report.json",
		DNSConfig: "/etc/hestia/dns.json", DNSPaths: "/run/hestia-dns/paths.json", DNSPolicy: "/var/lib/hestia-dns-policy/policy.json", DNSCache: "/var/lib/hestia-dns/cache.json", DNSReport: "/run/hestia-dns/report.json",
		Traffic: "/var/lib/hestia-traffic", GeoIPProposals: "/var/lib/hestia-geoip-proposals", GeoIPIndex: "/usr/share/hestia/geoip/country.bin", NetworkProfiles: "/etc/NetworkManager/system-connections", ResolvConf: "/etc/resolv.conf",
	}
}

// Keenetic returns a private Entware-oriented layout and never targets the firmware's root configuration paths.
func Keenetic() Layout {
	const config = "/opt/etc/hestia"
	const runtime = "/opt/var/run/hestia"
	const state = "/opt/var/lib/hestia"
	return Layout{
		Config: config, Snapshot: config + "/snapshot.json", BackendConfig: config + "/sing-box.json",
		Runtime: runtime, ServicesSocket: runtime + "/services.sock",
		PanelListen: config + "/panel-listen", PanelAssets: "/opt/share/hestia-panel/current",
		InstallLock: "/opt/var/lock/hestia-install.lock", BindingMarker: config + "/binding-managed",
		AWGStore: config + "/awg", AWGRuntime: runtime + "/awg", AWGReady: runtime + "/awg/ready", AWGHealth: runtime + "/awg/health.json", AWGRoutes: runtime + "/awg/routes.json",
		CountryPolicy: state + "/country-map/policy.json", QualitySettings: state + "/quality/settings.json", QualityRuntime: runtime + "/quality", QualityReport: runtime + "/quality/report.json",
		DNSConfig: config + "/dns.json", DNSPaths: runtime + "/dns/paths.json", DNSPolicy: state + "/dns-policy/policy.json", DNSCache: state + "/dns/cache.json", DNSReport: runtime + "/dns/report.json",
		Traffic: state + "/traffic", GeoIPProposals: state + "/geoip-proposals", GeoIPIndex: "/opt/share/hestia/geoip/country.bin", NetworkProfiles: config + "/network-profiles", ResolvConf: "/etc/resolv.conf",
	}
}
