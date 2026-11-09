//go:build !keenetic

// Package platform selects the concrete adapters for an installed Hestia build.
package platform

import (
	"context"
	"errors"

	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/network/linuxphysical"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/services/systemd"
)

// RunSupervisor refuses the Keenetic-only supervisor command in the default Linux build.
func RunSupervisor(context.Context) error {
	return errors.New("Keenetic service supervisor is unavailable")
}

// CheckManagedProcessesStopped refuses to infer process state in the Linux build.
func CheckManagedProcessesStopped() error { return errors.New("Keenetic process check is unavailable") }

// CheckSupervisorProcess refuses to validate a Keenetic PID in the Linux build.
func CheckSupervisorProcess(int) error { return errors.New("Keenetic process check is unavailable") }

// SupervisorReady refuses to query the Keenetic IPC endpoint in the Linux build.
func SupervisorReady(context.Context) error {
	return errors.New("Keenetic supervisor check is unavailable")
}

// ReconcileIngress refuses the Keenetic-only NDM callback request in the default Linux build.
func ReconcileIngress(context.Context) error {
	return errors.New("Keenetic ingress reconciliation is unavailable")
}

// QuiesceIngress refuses the Keenetic-only route lock in the default Linux build.
func QuiesceIngress(context.Context) error {
	return errors.New("Keenetic ingress route lock is unavailable")
}

// EnsureOpkgTun rejects the Keenetic-only NDM interface operation in the Linux build.
func EnsureOpkgTun() error { return errors.New("Keenetic OpkgTun is unavailable") }

// RemoveOpkgTun rejects the Keenetic-only NDM interface operation in the Linux build.
func RemoveOpkgTun() error { return errors.New("Keenetic OpkgTun is unavailable") }

// Physical creates the Linux NetworkManager and sysfs adapter for installed physical connections.
func Physical() network.Physical { return linuxphysical.Manager{} }

// Services creates the Linux service lifecycle adapter, preserving an optional fixed-command runner.
func Services(run func(context.Context, string, ...string) error) services.Manager {
	return systemd.Manager{Run: run}
}

// OfflineVerifier creates the Linux systemd-backed proof used before AWG route retirement.
func OfflineVerifier() services.Offline { return systemd.OfflineVerifier{} }
