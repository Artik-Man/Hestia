//go:build linux && keenetic

package awg

import (
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"github.com/Artik-Man/Hestia/internal/network/keeneticroute"
	"github.com/Artik-Man/Hestia/internal/platform"
	"github.com/Artik-Man/Hestia/internal/services"
)

// Installed platform composition selects the pinned Entware AWG runtime and Keenetic route adapter.
var (
	runtimeDriver   awgruntime.Driver = awgruntime.Entware{}
	offlineVerifier services.Offline  = platform.OfflineVerifier()
	routeRunner     RouteRunner       = keeneticroute.ExecRouteRunner{}
)
