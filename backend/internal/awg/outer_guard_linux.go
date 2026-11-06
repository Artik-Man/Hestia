package awg

import (
	"context"
	"github.com/Artik-Man/Hestia/internal/network/linuxroute"
	"github.com/Artik-Man/Hestia/internal/storage"
	"path/filepath"
)

// outerPolicy derives a terminal rule for the daemon's outer mark; local loopback routing precedes it and no tunnel table follows it.
func outerPolicy(slot int) (RoutePolicy, error) {
	policy, err := linuxroute.NewOuterPolicy(ExecRouteRunner{}, slot)
	if err != nil {
		return RoutePolicy{}, err
	}
	return wrapRoutePolicy(policy), nil
}

// outerBarrier changes only the recorded terminal rules for one validated slot. Installing refuses a pre-existing unowned rule.
func (p RoutePolicy) outerBarrier(ctx context.Context, id string, install bool) error {
	path := filepath.Join(storage.Installed().AWGRuntime, "outer-rule."+id)
	manifest := p.manifest(id)
	owned, err := loadRouteManifest(path, manifest)
	if err != nil || (!install && !owned) {
		return err
	}
	if err := p.OuterBarrier(ctx, owned, install, func() error { return writeRouteManifest(path, manifest) }); err != nil {
		return err
	}
	if !install {
		return removeRouteManifest(path)
	}
	return nil
}
