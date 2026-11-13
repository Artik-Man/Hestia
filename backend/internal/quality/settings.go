// Package quality measures independent transport exchanges through each configured gateway exit.
package quality

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Artik-Man/Hestia/internal/netaddress"
)

const (
	UDP   = "UDP"
	TCP   = "TCP"
	ICMP  = "ICMP"
	DNS   = "DNS"
	HTTPS = "HTTPS"
	HTTP3 = "HTTP3"

	// MaxSamplesPerExit bounds exact rolling history even for the largest accepted schedule.
	MaxSamplesPerExit = 32768
)

// QualitySettings retains the legacy migration seed and independently configured groups.
type QualitySettings struct {
	Groups        map[string]GroupSettings `json:"groups" nullable:"true"`
	WindowMinutes int                      `json:"windowMinutes" minimum:"1" maximum:"1440"`
	Checks        []QualityCheck           `json:"checks" minItems:"0" maxItems:"6" nullable:"false"`
}

// GroupSettings defines the scoring window and probes for all connections in one group.
type GroupSettings struct {
	WindowMinutes int            `json:"windowMinutes" minimum:"1" maximum:"1440"`
	Checks        []QualityCheck `json:"checks" minItems:"0" maxItems:"6" nullable:"false"`
}

// ForGroup returns a detached override, the legacy seed before migration, or defaults for a new group.
func (s QualitySettings) ForGroup(id string) GroupSettings {
	g, ok := s.Groups[id]
	if !ok {
		seed := s
		if s.Groups != nil {
			seed = DefaultSettings()
		}
		g = GroupSettings{WindowMinutes: seed.WindowMinutes, Checks: seed.Checks}
	}
	g.Checks = slices.Clone(g.Checks)
	for i := range g.Checks {
		g.Checks[i].Targets = slices.Clone(g.Checks[i].Targets)
	}
	return g
}

// Validate enforces the same scheduling and network boundaries for an individual group.
func (g GroupSettings) Validate() error {
	return (QualitySettings{WindowMinutes: g.WindowMinutes, Checks: g.Checks}).validateSchedule()
}

// QualityCheck configures one transport test against literal IP:port targets.
type QualityCheck struct {
	Protocol        string   `json:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
	Targets         []string `json:"targets" minItems:"1" maxItems:"8" nullable:"false"`
	IntervalSeconds int      `json:"intervalSeconds" minimum:"1" maximum:"3600"`
	TimeoutSeconds  int      `json:"timeoutSeconds" minimum:"1" maximum:"30"`
	DNSName         string   `json:"dnsName,omitempty" maxLength:"253"`
	ServerName      string   `json:"serverName,omitempty" maxLength:"253" doc:"Имя сервера для TLS и HTTP."`
	RequestPath     string   `json:"requestPath,omitempty" maxLength:"1024" doc:"Путь запроса на сервере, включая необязательную строку параметров."`
}

var protocols = [...]string{UDP, TCP, ICMP, DNS, HTTPS, HTTP3}

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
	if err := s.validateSchedule(); err != nil {
		return err
	}
	for id, group := range s.Groups {
		if strings.TrimSpace(id) == "" {
			return errors.New("пустой идентификатор группы проверок")
		}
		if err := group.Validate(); err != nil {
			return fmt.Errorf("группа %s: %w", id, err)
		}
	}
	return nil
}

// validateSchedule checks one bounded schedule without traversing group settings.
func (s QualitySettings) validateSchedule() error {
	if s.WindowMinutes < 1 || s.WindowMinutes > 1440 || s.Checks == nil || len(s.Checks) > len(protocols) {
		return errors.New("нужны окно от 1 до 1440 минут и список проверок")
	}
	seen := map[string]bool{}
	scheduled := 0
	for _, c := range s.Checks {
		if seen[c.Protocol] || !slices.Contains(protocols[:], c.Protocol) {
			return errors.New("допустима одна проверка каждого поддерживаемого типа")
		}
		seen[c.Protocol] = true
		if c.IntervalSeconds < 1 || c.IntervalSeconds > 3600 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 30 || c.TimeoutSeconds > c.IntervalSeconds {
			return fmt.Errorf("%s: допустимый интервал 1–3600 с, тайм-аут 1–30 с в пределах интервала", c.Protocol)
		}
		if len(c.Targets) < 1 || len(c.Targets) > 8 {
			return errors.New("для проверки требуется от одной до восьми целей")
		}
		if err := c.validateOptions(); err != nil {
			return err
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
			key, err := c.targetAddress(target)
			if err != nil || targets[key] {
				return fmt.Errorf("%s: укажите разные публичные адреса целей в формате проверки", c.Protocol)
			}
			targets[key] = true
		}
	}
	return nil
}

// validateOptions checks the DNS or HTTP-specific fields and rejects stray options from other probes.
func (c QualityCheck) validateOptions() error {
	if c.Protocol == UDP && len(c.Targets) != 2 {
		return errors.New("для UDP укажите два резолвера разных операторов")
	}
	switch c.Protocol {
	case UDP, DNS:
		if !validName(c.DNSName) {
			return errors.New("для DNS-запроса укажите корректное доменное имя")
		}
	default:
		if c.DNSName != "" {
			return errors.New("доменное имя запроса доступно только для DNS и UDP")
		}
	}
	if c.Protocol != HTTPS && c.Protocol != HTTP3 {
		if c.ServerName != "" || c.RequestPath != "" {
			return errors.New("имя сервера и путь доступны только для HTTPS и HTTP/3")
		}
		return nil
	}
	if !validName(c.ServerName) || strings.HasSuffix(c.ServerName, ".") {
		return errors.New("укажите корректное имя HTTPS-сервера")
	}
	if _, err := netip.ParseAddr(c.ServerName); err == nil {
		return errors.New("укажите DNS-имя HTTPS-сервера")
	}
	u, err := url.ParseRequestURI(c.RequestPath)
	if err != nil || len(c.RequestPath) > 1024 || !strings.HasPrefix(c.RequestPath, "/") || strings.HasPrefix(c.RequestPath, "//") || strings.ContainsAny(c.RequestPath, "#\\") || u.IsAbs() || u.Host != "" || u.User != nil {
		return errors.New("путь запроса должен начинаться с / и принадлежать выбранному серверу")
	}
	return nil
}

// targetAddress normalizes the literal probe destination and enforces the transport's port policy.
func (c QualityCheck) targetAddress(target string) (netip.AddrPort, error) {
	if c.Protocol == ICMP {
		ip, err := netip.ParseAddr(target)
		if err != nil || !netaddress.Public(ip.Unmap()) {
			return netip.AddrPort{}, errors.New("для ICMP нужен публичный IP без порта")
		}
		return netip.AddrPortFrom(ip.Unmap(), 0), nil
	}
	ep, err := netip.ParseAddrPort(target)
	if err != nil || ep.Port() == 0 || !netaddress.Public(ep.Addr().Unmap()) || ((c.Protocol == UDP || c.Protocol == DNS) && ep.Port() != 53) {
		return netip.AddrPort{}, errors.New("нужен публичный IP:порт, для DNS — порт 53")
	}
	return netip.AddrPortFrom(ep.Addr().Unmap(), ep.Port()), nil
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
