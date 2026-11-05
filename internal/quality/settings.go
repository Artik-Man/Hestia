// Package quality measures independent transport exchanges through each configured gateway exit.
package quality

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

const (
	UDP = "UDP"
	TCP = "TCP"

	// MaxSamplesPerExit bounds exact rolling history even for the largest accepted schedule.
	MaxSamplesPerExit = 32768
)

// QualitySettings defines a common scoring window and the checks shared by every exit.
type QualitySettings struct {
	WindowMinutes int            `json:"windowMinutes" minimum:"1" maximum:"1440"`
	Checks        []QualityCheck `json:"checks" minItems:"0" maxItems:"2" nullable:"false"`
}

// QualityCheck configures one transport test against literal IP:port targets.
type QualityCheck struct {
	Protocol        string   `json:"protocol" enum:"UDP,TCP"`
	Targets         []string `json:"targets" minItems:"1" maxItems:"8" nullable:"false"`
	IntervalSeconds int      `json:"intervalSeconds" minimum:"1" maximum:"3600"`
	TimeoutSeconds  int      `json:"timeoutSeconds" minimum:"1" maximum:"30"`
	DNSName         string   `json:"dnsName,omitempty" maxLength:"253"`
}

type Settings = QualitySettings
type Check = QualityCheck

// DefaultSettings returns fresh settings with two independent resolver operators and a one-hour window.
func DefaultSettings() Settings {
	return Settings{WindowMinutes: 60, Checks: []Check{
		{Protocol: UDP, Targets: []string{"1.1.1.1:53", "8.8.8.8:53"}, IntervalSeconds: 30, TimeoutSeconds: 3, DNSName: "example.com"},
		{Protocol: TCP, Targets: []string{"1.1.1.1:443", "8.8.8.8:443"}, IntervalSeconds: 30, TimeoutSeconds: 3},
	}}
}

// ValidateSettings verifies the complete schedule before it can replace the worker configuration.
func ValidateSettings(s Settings) error { return s.Validate() }

// Validate accepts only distinct supported protocols, bounded scheduling and distinct public targets for each test.
func (s QualitySettings) Validate() error {
	if s.WindowMinutes < 1 || s.WindowMinutes > 1440 || s.Checks == nil || len(s.Checks) > 2 {
		return errors.New("нужны окно от 1 до 1440 минут и список проверок")
	}
	seen := map[string]bool{}
	scheduled := 0
	for _, c := range s.Checks {
		if seen[c.Protocol] || (c.Protocol != UDP && c.Protocol != TCP) {
			return errors.New("допустима одна проверка каждого типа TCP или UDP")
		}
		seen[c.Protocol] = true
		if c.IntervalSeconds < 1 || c.IntervalSeconds > 3600 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 || c.TimeoutSeconds > c.IntervalSeconds {
			return fmt.Errorf("%s: допустимый интервал 1–3600 с, тайм-аут 1–30 с в пределах интервала", c.Protocol)
		}
		if len(c.Targets) < 1 || len(c.Targets) > 8 {
			return errors.New("для проверки требуется от одной до восьми целей")
		}
		if c.Protocol == UDP && (len(c.Targets) != 2 || !validName(c.DNSName)) {
			return errors.New("для UDP укажите два резолвера разных операторов и корректное DNS-имя")
		}
		if c.Protocol == TCP && c.DNSName != "" {
			return errors.New("поле DNS-имени допустимо только для UDP")
		}
		// A completion can move by one timeout relative to its scheduled start.
		// Include the boundaries of both the completion window and the in-flight round.
		rounds := (s.WindowMinutes*60+c.IntervalSeconds-1)/c.IntervalSeconds + 2
		scheduled += rounds * len(c.Targets)
		if scheduled > MaxSamplesPerExit {
			return fmt.Errorf("слишком много проб за окно (предел %d на подключение). Увеличьте интервал или сократите окно", MaxSamplesPerExit)
		}
		targets := map[netip.AddrPort]bool{}
		for _, target := range c.Targets {
			ep, err := netip.ParseAddrPort(target)
			ip := ep.Addr().Unmap()
			key := netip.AddrPortFrom(ip, ep.Port())
			if err != nil || ep.Port() == 0 || !publicTarget(ip) || targets[key] || (c.Protocol == UDP && ep.Port() != 53) {
				return fmt.Errorf("%s: требуется уникальный публичный IP:порт (для UDP порт 53)", c.Protocol)
			}
			targets[key] = true
		}
	}
	return nil
}

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

// publicTarget restricts probes to public unicast destinations, excluding tunnels that can embed private IPv4 targets.
func publicTarget(ip netip.Addr) bool {
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

// validName accepts an ASCII DNS host name with optional trailing root label.
func validName(s string) bool {
	n := strings.TrimSuffix(s, ".")
	if len(n) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(n, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// LoadSettings uses defaults only for a missing settings file and rejects incomplete or invalid stored JSON.
func LoadSettings(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var s Settings
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Settings{}, err
	}
	if err := d.Decode(new(json.RawMessage)); err != io.EOF {
		return Settings{}, errors.New("unexpected trailing settings data")
	}
	return s, s.Validate()
}

// SaveSettings validates and durably replaces a settings file in its existing service-owned directory.
func SaveSettings(path string, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".quality-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// The independent worker reads these non-secret settings under its own service account.
	if err = f.Chmod(0644); err == nil {
		err = json.NewEncoder(f).Encode(s)
	}
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
