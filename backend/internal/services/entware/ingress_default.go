//go:build linux && !keenetic

package entware

import (
	"context"
	"errors"
)

// runIngressLifecycle keeps the platform-neutral Entware supervisor API buildable without Keenetic route support.
func runIngressLifecycle(ctx context.Context, _ *processTable, ready chan<- error) error {
	ready <- nil
	<-ctx.Done()
	return nil
}

// reconcileIngressGuard is unavailable when the build has no Keenetic policy and route adapters.
func reconcileIngressGuard(context.Context) error {
	return errors.New("Keenetic ingress route reconciliation is unavailable")
}

// quiesceIngressRoute is unavailable when the build has no Keenetic route adapter.
func quiesceIngressRoute(context.Context) error {
	return errors.New("Keenetic ingress route lock is unavailable")
}
