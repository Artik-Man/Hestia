//go:build keenetic

package platform

import (
	"context"

	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/network/keeneticphysical"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/services/entware"
)

// Physical selects the read-only Keenetic RCI inventory adapter; Wi-Fi mutations remain unsupported.
func Physical() network.Physical { return keeneticphysical.InstalledManager() }

// Services creates the Entware supervisor client for Keenetic lifecycle requests.
func Services(_ func(context.Context, string, ...string) error) services.Manager {
	return entware.Manager{}
}

// OfflineVerifier derives process stop proof from the Entware supervisor's retained handles.
func OfflineVerifier() services.Offline { return entware.OfflineVerifier{} }

// RunSupervisor starts the foreground process owner used by the Entware init script.
func RunSupervisor(ctx context.Context) error { return entware.RunSupervisor(ctx) }

// CheckManagedProcessesStopped verifies that no Keenetic Hestia service process remains alive.
func CheckManagedProcessesStopped() error { return entware.CheckManagedProcessesStopped() }

// CheckSupervisorProcess verifies the recorded process is the exact foreground service supervisor.
func CheckSupervisorProcess(pid int) error { return entware.CheckSupervisorProcess(pid) }

// SupervisorReady reports whether the root-only IPC endpoint answers for its managed service table.
func SupervisorReady(ctx context.Context) error { return entware.SupervisorReady(ctx) }

// ReconcileIngress executes a synchronous root-supervisor policy refresh for an NDM event.
func ReconcileIngress(ctx context.Context) error { return entware.ReconcileIngress(ctx) }

// QuiesceIngress waits for standalone hook operations before opkg replaces the route lock file.
func QuiesceIngress(ctx context.Context) error { return entware.QuiesceIngress(ctx) }
