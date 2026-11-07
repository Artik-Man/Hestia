//go:build linux && keenetic

package awg

import (
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"github.com/Artik-Man/Hestia/internal/network/keeneticroute"
	"github.com/Artik-Man/Hestia/internal/platform"
	"github.com/Artik-Man/Hestia/internal/services"
)

// Installed platform composition disables unverified AWG operations on Keenetic builds.
var (
	runtimeDriver   awgruntime.Driver = awgruntime.Unsupported{}
	offlineVerifier services.Offline  = platform.OfflineVerifier()
	routeRunner     RouteRunner       = keeneticroute.ExecRouteRunner{}
)
