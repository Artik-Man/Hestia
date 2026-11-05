// Package observer compares delivery over named connections without changing routes.
package observer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"
)

type Connection struct {
	ID        string `json:"id"`
	Interface string `json:"interface"`
}

type Target struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type Settings struct {
	Group                     string
	Connections               []Connection
	Targets                   []Target
	Interval, Timeout, Window time.Duration
	MinSamples, MarginPercent int
}

// Decode validates one group's configuration and applies sampling defaults.
func Decode(data []byte) (Settings, error) {
	var cfg struct {
		Group         string       `json:"group"`
		Connections   []Connection `json:"connections"`
		Targets       []Target     `json:"targets"`
		Interval      string       `json:"interval"`
		Timeout       string       `json:"timeout"`
		Window        string       `json:"window"`
		MinSamples    *int         `json:"min_samples"`
		MarginPercent *int         `json:"margin_percent"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Settings{}, fmt.Errorf("observer config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Settings{}, fmt.Errorf("unexpected trailing configuration")
	}
	s := Settings{Group: cfg.Group, Connections: cfg.Connections, Targets: cfg.Targets, MinSamples: 100, MarginPercent: 5}
	if cfg.MinSamples != nil {
		s.MinSamples = *cfg.MinSamples
	}
	if cfg.MarginPercent != nil {
		s.MarginPercent = *cfg.MarginPercent
	}
	var err error
	if s.Interval, err = duration(cfg.Interval, 10*time.Second); err != nil {
		return Settings{}, err
	}
	if s.Timeout, err = duration(cfg.Timeout, time.Second); err != nil {
		return Settings{}, err
	}
	if s.Window, err = duration(cfg.Window, time.Hour); err != nil {
		return Settings{}, err
	}
	return s, s.validate()
}

// duration parses a positive interval or substitutes the default for a missing value.
func duration(value string, def time.Duration) (time.Duration, error) {
	if value == "" {
		return def, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid positive duration %q", value)
	}
	return d, nil
}

// validate checks identifiers, literal destinations and resource bounds before any socket is opened.
func (s Settings) validate() error {
	n := len(s.Connections)
	m := len(s.Targets)
	if !validID(s.Group) || n < 1 || n > 32 || m < 1 || m > 64 || n*m > 128 {
		return fmt.Errorf("require a named group, 1..32 connections, 1..64 targets and at most 128 simultaneous probes")
	}
	if s.Interval < 20*time.Millisecond || s.Timeout <= 0 || s.Timeout > s.Interval || s.Window < s.Interval {
		return fmt.Errorf("require interval >= 20ms, timeout <= interval, window >= interval")
	}
	rounds := int64(1 + (s.Window-1)/s.Interval)
	if rounds > 1_000_000/int64(n*m) || s.MinSamples < 1 || int64(s.MinSamples) > rounds || s.MarginPercent < 1 || s.MarginPercent > 100 {
		return fmt.Errorf("invalid thresholds or window larger than one million individual samples")
	}
	ids, ifaces := map[string]bool{}, map[string]bool{}
	for _, c := range s.Connections {
		if !validID(c.ID) || !validID(c.Interface) || len(c.Interface) > 15 || ids[c.ID] || ifaces[c.Interface] {
			return fmt.Errorf("invalid or duplicate connection %q / interface %q", c.ID, c.Interface)
		}
		ids[c.ID], ifaces[c.Interface] = true, true
	}
	scopes := map[string]bool{}
	for _, t := range s.Targets {
		addr, err := netip.ParseAddr(t.Address)
		key := t.Address + "/" + t.Protocol
		if err != nil || !addr.Is4() || addr.IsMulticast() || addr.IsUnspecified() || t.Address == "255.255.255.255" || t.Port < 1 || t.Port > 65535 || (t.Protocol != "tcp" && t.Protocol != "udp") || scopes[key] {
			return fmt.Errorf("invalid or duplicate target %q, protocol %q, port %d", t.Address, t.Protocol, t.Port)
		}
		scopes[key] = true
	}
	return nil
}

// validID permits short unambiguous names for a group, connection or Linux interface.
func validID(s string) bool {
	return len(s) > 0 && len(s) <= 64 && strings.IndexFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("_.:-", r))
	}) < 0
}
