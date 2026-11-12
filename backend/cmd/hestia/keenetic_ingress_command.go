//go:build linux && arm64 && !android && keenetic

package main

import (
	"context"

	"github.com/Artik-Man/Hestia/internal/binding"
)

// runKeeneticIngress applies the transactional OpkgTun profile migration in a Keenetic build.
func runKeeneticIngress(ctx context.Context, enabled bool) error {
	return binding.Installed().SetKeeneticIngress(ctx, enabled)
}
