//go:build !keenetic

package binding

import "github.com/Artik-Man/Hestia/internal/panelmodel"

const (
	keeneticUplinkUnderlayID  = ""
	keeneticOpkgTunUnderlayID = ""
)

// PlatformUnderlayID returns the platform-specific direct transport ID, which is unavailable in the default build.
func PlatformUnderlayID() string { return "" }

// platformUnderlayCandidates lists only direct transports supplied by the selected platform.
func platformUnderlayCandidates() []panelmodel.AWGUnderlayCandidate { return nil }

// ensurePlatformUnderlay rejects platform-specific IDs that are not installed on this build.
func ensurePlatformUnderlay(*storedProfile, string) error { return ErrInvalidConnector }

// ensureOpkgTunUnderlay rejects the Keenetic-only OpkgTun transport in the default Linux build.
func ensureOpkgTunUnderlay(*storedProfile) error { return ErrInvalidConnector }
