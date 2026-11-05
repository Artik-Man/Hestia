// Package controller applies one routing decision to an existing local sing-box selector.
package controller

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Artik-Man/Hestia/internal/routing"
)

const deny = "deny"

// Config describes a complete availability snapshot. Group and exit IDs are sing-box tags.
type Config struct {
	Groups         []routing.Group   `json:"groups"`
	Lists          []routing.List    `json:"lists"`
	Healthy        map[string]bool   `json:"healthy"`
	ConnectorKinds map[string]string `json:"connectorKinds,omitempty"`
}

// Decode parses a single JSON snapshot and rejects unknown struct fields or
// trailing content. CheckSnapshot also validates its routing configuration.
func Decode(data []byte) (Config, error) {
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid snapshot: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, fmt.Errorf("unexpected content after snapshot")
	}
	return cfg, nil
}

// validate checks tag uniqueness, list identifiers, and availability references
// before the routing model validates group bindings and domain masks.
func (cfg Config) validate() error {
	if cfg.Healthy == nil {
		return fmt.Errorf("snapshot requires a healthy object")
	}
	tags := map[string]bool{deny: true}
	exits := make(map[string]bool)
	for _, g := range cfg.Groups {
		for _, tag := range append([]string{g.ID}, g.Exits...) {
			if tag == "" || tag == "." || tag == ".." || strings.ContainsAny(tag, "/\\?#") || strings.TrimSpace(tag) != tag || tags[tag] {
				return fmt.Errorf("invalid, duplicate or reserved sing-box tag %q", tag)
			}
			tags[tag] = true
		}
		for _, e := range g.Exits {
			exits[e] = true
		}
	}
	for e := range cfg.Healthy {
		if !exits[e] {
			return fmt.Errorf("unknown exit in availability: %q", e)
		}
	}
	for e, kind := range cfg.ConnectorKinds {
		if !exits[e] || (kind != "awg" && kind != "hysteria2") {
			return fmt.Errorf("unknown or unsupported connector kind for exit %q", e)
		}
	}
	ids := make(map[string]bool)
	for _, l := range cfg.Lists {
		if l.ID == "" || ids[l.ID] {
			return fmt.Errorf("empty or duplicate list ID %q", l.ID)
		}
		ids[l.ID] = true
	}
	return nil
}
