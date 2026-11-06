package storage

import "testing"

// TestLinuxLayout pins installed paths so refactoring cannot silently migrate persisted state.
func TestLinuxLayout(t *testing.T) {
	layout := Linux()
	for _, entry := range []struct{ got, want string }{
		{layout.Config, "/etc/hestia"},
		{layout.Snapshot, "/etc/hestia/snapshot.json"},
		{layout.BackendConfig, "/etc/hestia/sing-box.json"},
		{layout.InstallLock, "/run/hestia-install.lock"},
		{layout.BindingMarker, "/etc/tmpfiles.d/hestia-binding.conf"},
		{layout.AWGStore, "/etc/hestia/awg"},
		{layout.AWGRuntime, "/run/hestia-awg"},
		{layout.AWGReady, "/run/hestia-awg/ready"},
		{layout.AWGHealth, "/run/hestia-awg/health.json"},
		{layout.AWGRoutes, "/run/hestia-awg/routes.json"},
		{layout.CountryPolicy, "/var/lib/hestia-country-map/policy.json"},
		{layout.QualitySettings, "/var/lib/hestia-quality-settings/settings.json"},
		{layout.QualityRuntime, "/run/hestia-quality"},
		{layout.QualityReport, "/run/hestia-quality/report.json"},
		{layout.DNSPaths, "/run/hestia-dns/paths.json"},
		{layout.DNSPolicy, "/var/lib/hestia-dns-policy/policy.json"},
		{layout.DNSCache, "/var/lib/hestia-dns/cache.json"},
		{layout.DNSReport, "/run/hestia-dns/report.json"},
		{layout.Traffic, "/var/lib/hestia-traffic"},
		{layout.GeoIPProposals, "/var/lib/hestia-geoip-proposals"},
		{layout.GeoIPIndex, "/usr/share/hestia/geoip/country.bin"},
		{layout.NetworkProfiles, "/etc/NetworkManager/system-connections"},
		{layout.ResolvConf, "/etc/resolv.conf"},
	} {
		if entry.got != entry.want {
			t.Errorf("path changed: got %q, want %q", entry.got, entry.want)
		}
	}
}
