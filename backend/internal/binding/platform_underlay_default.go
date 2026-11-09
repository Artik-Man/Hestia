//go:build !keenetic

package binding

import "github.com/Artik-Man/Hestia/internal/panelmodel"

const (
	keeneticUplinkUnderlayID  = ""
	keeneticOpkgTunUnderlayID = ""
)

// PlatformUnderlayID returns the platform-specific direct transport ID, which is unavailable in the default build.
func PlatformUnderlayID() string { return "" }

// PlatformOutputID returns the stable direct egress ID used by the Linux gateway profile.
func PlatformOutputID() string { return "keenetic-direct" }

// platformOutputNeedsDeviceBinding reports whether adding the platform output resolves a device at runtime.
func platformOutputNeedsDeviceBinding() bool { return false }

// platformUnderlayCandidates lists only direct transports supplied by the selected platform.
func platformUnderlayCandidates() []panelmodel.AWGUnderlayCandidate { return nil }

// platformChannelRole maps Linux gateway endpoint IDs to stable panel roles without exposing interface names.
func platformChannelRole(id string) panelmodel.ChannelRole {
	switch id {
	case "wg-keenetic":
		return panelmodel.ChannelRoleInput
	case "keenetic-direct":
		return panelmodel.ChannelRoleOutput
	default:
		return ""
	}
}

// ensurePlatformUnderlay rejects platform-specific IDs that are not installed on this build.
func ensurePlatformUnderlay(*storedProfile, string) error { return ErrInvalidConnector }

// ensureOpkgTunUnderlay rejects the Keenetic-only OpkgTun transport in the default Linux build.
func ensureOpkgTunUnderlay(*storedProfile) error { return ErrInvalidConnector }
