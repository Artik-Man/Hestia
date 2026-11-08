//go:build keenetic

package binding

import (
	"slices"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

const keeneticUplinkUnderlayID = "keenetic-uplink"

// PlatformUnderlayID returns the stable routing ID reserved by this platform for its discovered internet uplink.
func PlatformUnderlayID() string { return keeneticUplinkUnderlayID }

// platformUnderlayCandidates publishes the managed Keenetic default-route transport before it is added to a profile.
func platformUnderlayCandidates() []panelmodel.AWGUnderlayCandidate {
	return []panelmodel.AWGUnderlayCandidate{{ID: keeneticUplinkUnderlayID, Type: "direct", Name: "Интернет"}}
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
