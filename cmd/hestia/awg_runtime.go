//go:build linux && arm64 && !android

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Artik-Man/Hestia/internal/awg"
)

// runAWGRuntimeCommand requires root and supervises the fixed active AWG connector until systemd stops it.
func runAWGRuntimeCommand() int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "AWG runtime requires root")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := (awg.InstalledRuntime{}).ServeReadyConnector(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "AWG runtime stopped: "+err.Error())
		return 1
	}
	return 0
}
