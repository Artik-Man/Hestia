package binding

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"

	"github.com/Artik-Man/Hestia/internal/controller"
)

// connectionEnabled reports the persistent administrative state, defaulting old profiles to enabled.
func (p storedProfile) connectionEnabled(id string) bool {
	return !slices.Contains(p.DisabledConnections, id)
}

// virtualConnection accepts saved VPN exits but excludes direct channels and platform ingress.
func (p storedProfile) virtualConnection(id string) bool {
	if platformChannelRole(id) != "" {
		return false
	}
	if connectorIndex(p.Connectors, id) >= 0 {
		return true
	}
	for _, item := range p.Hysteria2 {
		if item.ID == id {
			return true
		}
	}
	for _, item := range p.Interfaces {
		if item.ID == id && item.Type == "wireguard" {
			return true
		}
	}
	return false
}

// ConnectionEnabled reads one connection's durable switch state under the installation lock.
func (e Engine) ConnectionEnabled(id string) (bool, error) {
	lock, err := e.acquire(false)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	current, err := e.physicalProfile()
	if err != nil {
		return false, err
	}
	if !current.virtualConnection(id) {
		return false, ErrNotFound
	}
	return current.connectionEnabled(id), nil
}

// SetConnectionEnabled applies an administrative VPN state through the verified generation transaction.
// Group placement and secrets are retained; disabled public routes become explicit blocks.
func (e Engine) SetConnectionEnabled(ctx context.Context, id string, enabled bool) error {
	check := func(data []byte, staged bool) error {
		config, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if staged && !enabled && config.Healthy[id] {
			return ErrUnavailable
		}
		return nil
	}
	prepare := func(stage string) error {
		current, err := e.physicalProfile()
		if err != nil {
			return err
		}
		if !current.virtualConnection(id) {
			return ErrNotFound
		}
		if !enabled {
			if err := e.archiveNativeEndpoint(&current, id); err != nil {
				return err
			}
			if current.connectionEnabled(id) {
				current.DisabledConnections = append(current.DisabledConnections, id)
			}
		} else {
			current.DisabledConnections = slices.DeleteFunc(current.DisabledConnections, func(value string) bool { return value == id })
		}
		return compileConnectorGeneration(ctx, e, stage, current)
	}
	return e.apply(ctx, prepare, check, false)
}

// archiveNativeEndpoint retains a native VPN's compiled secrets only in the private source generation.
// The compiler removes its live endpoint while disabled and restores it on re-enable.
func (e Engine) archiveNativeEndpoint(profile *storedProfile, id string) error {
	native := false
	for _, item := range profile.Interfaces {
		native = native || (item.ID == id && item.Type == "wireguard")
	}
	if !native {
		return nil
	}
	if _, exists := profile.DisabledNativeEndpoints[id]; exists {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "sing-box.json"))
	if err != nil {
		return ErrUnavailable
	}
	var backend struct {
		Endpoints []json.RawMessage `json:"endpoints"`
		DNS       struct {
			Servers []json.RawMessage `json:"servers"`
		} `json:"dns"`
	}
	if json.Unmarshal(data, &backend) != nil {
		return ErrUnavailable
	}
	var archived struct {
		Endpoint json.RawMessage `json:"endpoint"`
		Server   json.RawMessage `json:"server"`
	}
	for _, raw := range backend.Endpoints {
		var item struct {
			Tag  string `json:"tag"`
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &item) != nil {
			return ErrUnavailable
		}
		if item.Tag == id && item.Type == "wireguard" {
			archived.Endpoint = raw
		}
	}
	for _, raw := range backend.DNS.Servers {
		var item struct {
			Tag    string `json:"tag"`
			Detour string `json:"detour"`
		}
		if json.Unmarshal(raw, &item) != nil {
			return ErrUnavailable
		}
		if item.Tag == "dns-"+id && item.Detour == id {
			archived.Server = raw
		}
	}
	if archived.Endpoint == nil || archived.Server == nil {
		return ErrUnavailable
	}
	raw, err := json.Marshal(archived)
	if err != nil {
		return ErrUnavailable
	}
	if profile.DisabledNativeEndpoints == nil {
		profile.DisabledNativeEndpoints = map[string]json.RawMessage{}
	}
	profile.DisabledNativeEndpoints[id] = raw
	return nil
}
