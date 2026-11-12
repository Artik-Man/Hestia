//go:build linux && keenetic

package entware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/network/keeneticroute"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const (
	ingressReconcileInterval = time.Second
	ingressReconcileTimeout  = 15 * time.Second
	ingressRouteLockPath     = "/opt/var/lock/hestia-ingress.lock"
)

// runIngressLifecycle guards selected policy marks before the router starts and reconciles the TUN route while services change.
func runIngressLifecycle(ctx context.Context, table *processTable, ready chan<- error) error {
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		ready <- errors.New("Keenetic ingress policy reader is unavailable")
		return err
	}
	reconciler, err := keeneticroute.NewIngressReconciler(client, keeneticroute.NetlinkIngressOps{OwnershipPath: storage.Installed().IngressRuleState}, "br0", "opkgtun0")
	if err != nil {
		ready <- err
		return err
	}
	reconcile := func(reconcileCtx context.Context, forceGuard bool) error {
		return withIngressRouteLock(reconcileCtx, func() error {
			return reconciler.Reconcile(reconcileCtx, !forceGuard && managedIngressBackendReady(table))
		})
	}
	table.setIngressSync(reconcile)
	defer table.setIngressSync(nil)
	ticker := time.NewTicker(ingressReconcileInterval)
	defer ticker.Stop()
	readySent := false
	for {
		reconcileCtx, cancel := context.WithTimeout(ctx, ingressReconcileTimeout)
		err = table.reconcileIngress(reconcileCtx, false)
		cancel()
		if err != nil {
			log.Printf("Keenetic ingress reconciliation failed; retaining guarded state: %v", err)
		} else if !readySent {
			ready <- nil
			readySent = true
		}
		select {
		case <-ctx.Done():
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
			if cleanupErr := table.reconcileIngress(cleanupCtx, true); cleanupErr != nil {
				log.Printf("Keenetic ingress could not enter guarded shutdown state: %v", cleanupErr)
				cleanupCancel()
				return fmt.Errorf("Keenetic ingress guarded shutdown failed: %w", cleanupErr)
			}
			cleanupCancel()
			return nil
		case <-ticker.C:
		}
	}
}

// reconcileIngressGuard performs a standalone fail-closed snapshot before the service supervisor is ready.
func reconcileIngressGuard(ctx context.Context) error {
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		return errors.New("Keenetic ingress policy reader is unavailable")
	}
	reconciler, err := keeneticroute.NewIngressReconciler(client, keeneticroute.NetlinkIngressOps{OwnershipPath: storage.Installed().IngressRuleState}, "br0", "opkgtun0")
	if err != nil {
		return err
	}
	return withIngressRouteLock(ctx, func() error {
		maintenance, err := packageMaintenanceState()
		if err != nil {
			return err
		}
		if maintenance {
			return nil
		}
		return reconciler.Reconcile(ctx, false)
	})
}

// quiesceIngressRoute installs guard-only policy state while draining earlier hooks before package replacement.
func quiesceIngressRoute(ctx context.Context) error {
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		return errors.New("Keenetic ingress policy reader is unavailable")
	}
	reconciler, err := keeneticroute.NewIngressReconciler(client, keeneticroute.NetlinkIngressOps{OwnershipPath: storage.Installed().IngressRuleState}, "br0", "opkgtun0")
	if err != nil {
		return err
	}
	return withIngressRouteLock(ctx, func() error { return reconciler.Reconcile(ctx, false) })
}

// withIngressRouteLock serializes standalone NDM hook reconciliation with the resident supervisor.
func withIngressRouteLock(ctx context.Context, operation func() error) error {
	file, err := os.OpenFile(ingressRouteLockPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("Keenetic ingress route lock is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return errors.New("Keenetic ingress route lock cannot be inspected")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("Keenetic ingress route lock ownership is invalid")
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			return operation()
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return errors.New("Keenetic ingress route lock cannot be acquired")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// managedIngressBackendReady activates policy routes only when the supervisor owns a running router with the exact managed TUN inbound.
func managedIngressBackendReady(table *processTable) bool {
	state, err := table.status(services.Service{Kind: services.Router})
	if err != nil || state != services.Active {
		return false
	}
	data, err := readManagedFile(storage.Installed().BackendConfig, 8<<20)
	if err != nil {
		return false
	}
	return hasManagedIngress(data)
}
