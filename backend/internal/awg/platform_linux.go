//go:build linux

package awg

import (
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/services/systemd"
)

// Installed platform composition keeps daemon and stop-proof mechanisms outside connector coordination.
var (
	runtimeDriver   awgruntime.Driver = awgruntime.Linux{}
	offlineVerifier services.Offline  = systemd.OfflineVerifier{}
)
