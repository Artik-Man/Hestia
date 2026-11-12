//go:build keenetic

package binding

import (
	"encoding/json"
	"slices"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

const (
	keeneticUplinkUnderlayID  = "keenetic-uplink"
	keeneticOpkgTunUnderlayID = "keenetic-opkgtun"
)

// PlatformUnderlayID returns the stable routing ID reserved by this platform for its discovered internet uplink.
func PlatformUnderlayID() string { return keeneticUplinkUnderlayID }

// PlatformOutputID returns the stable direct egress ID supplied by the Keenetic gateway.
func PlatformOutputID() string { return keeneticUplinkUnderlayID }

// platformOutputNeedsDeviceBinding reports that the Keenetic WAN device must be verified when adding the output.
func platformOutputNeedsDeviceBinding() bool { return true }

// platformUnderlayCandidates publishes the managed Keenetic default-route transport before it is added to a profile.
func platformUnderlayCandidates() []panelmodel.AWGUnderlayCandidate {
	return []panelmodel.AWGUnderlayCandidate{
		{ID: keeneticUplinkUnderlayID, Type: "direct", Name: "Выход"},
		{ID: keeneticOpkgTunUnderlayID, Type: "direct", Name: "Вход"},
	}
}

// platformChannelRole maps Keenetic endpoint IDs to stable panel roles without exposing NDM or TUN names.
func platformChannelRole(id string) panelmodel.ChannelRole {
	switch id {
	case keeneticOpkgTunUnderlayID:
		return panelmodel.ChannelRoleInput
	case keeneticUplinkUnderlayID:
		return panelmodel.ChannelRoleOutput
	default:
		return ""
	}
}

// ensureOpkgTunUnderlay installs the owned OpkgTun route interface without making it a general group exit.
func ensureOpkgTunUnderlay(profile *storedProfile) error {
	found := false
	for _, item := range profile.Interfaces {
		if item.ID != keeneticOpkgTunUnderlayID {
			continue
		}
		if item.Type != "direct" || item.BindInterface != "opkgtun0" {
			return ErrInvalidConnector
		}
		found = true
	}
	if !found {
		profile.Interfaces = append(profile.Interfaces, storedInterface{
			ID: keeneticOpkgTunUnderlayID, Type: "direct", BindInterface: "opkgtun0",
		})
	}
	return ensureManagedOpkgTunInbound(profile)
}

// ensureManagedOpkgTunInbound adds the fixed ingress when a legacy profile first selects OpkgTun as VPN underlay.
func ensureManagedOpkgTunInbound(profile *storedProfile) error {
	type inbound struct {
		Type          string   `json:"type"`
		Tag           string   `json:"tag"`
		InterfaceName string   `json:"interface_name"`
		Address       []string `json:"address"`
		MTU           int      `json:"mtu"`
		AutoRoute     bool     `json:"auto_route"`
		Stack         string   `json:"stack"`
	}
	want := inbound{Type: "tun", Tag: "hestia-keenetic-ingress", InterfaceName: "opkgtun0", Address: []string{"172.31.250.2/30"}, MTU: 1500, AutoRoute: false, Stack: "gvisor"}
	for _, raw := range profile.Inbounds {
		var item inbound
		if err := json.Unmarshal(raw, &item); err != nil {
			return ErrInvalidConnector
		}
		if item.Tag == want.Tag {
			if item.Type != want.Type || item.InterfaceName != want.InterfaceName || item.MTU != want.MTU || item.AutoRoute || item.Stack != want.Stack || len(item.Address) != 1 || item.Address[0] != want.Address[0] {
				return ErrInvalidConnector
			}
			return nil
		}
	}
	encoded, err := json.Marshal(want)
	if err != nil {
		return ErrInvalidConnector
	}
	profile.Inbounds = append(profile.Inbounds, encoded)
	return nil
}

// ensurePlatformUnderlay adds the verified current default-route device only when a VPN chooses this transport.
func ensurePlatformUnderlay(profile *storedProfile, device string) error {
	if device == "" || len(device) > 15 {
		return ErrInvalidConnector
	}
	if len(profile.Groups) == 0 {
		return ErrInvalidConnector
	}
	found := false
	for _, item := range profile.Interfaces {
		if item.ID == keeneticUplinkUnderlayID {
			if item.Type != "direct" || item.BindInterface != device {
				return ErrInvalidConnector
			}
			found = true
		}
	}
	if !found {
		profile.Interfaces = append(profile.Interfaces, storedInterface{
			ID: keeneticUplinkUnderlayID, Type: "direct", BindInterface: device,
		})
	}
	groups := 0
	for _, group := range profile.Groups {
		if slices.Contains(group.Exits, keeneticUplinkUnderlayID) {
			groups++
		}
	}
	if groups > 1 {
		return ErrInvalidConnector
	}
	if groups == 0 {
		profile.Groups[0].Exits = append(profile.Groups[0].Exits, keeneticUplinkUnderlayID)
	}
	return nil
}
