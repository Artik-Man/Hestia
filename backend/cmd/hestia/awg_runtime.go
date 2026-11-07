//go:build linux && arm64 && !android

package main

import (
	"context"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/platform"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
)

// runAWGRuntimeCommand requires root and supervises the named connector (empty ID selects the legacy singleton) until systemd stops it.
func runAWGRuntimeCommand(id string) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "AWG runtime requires root")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := (awg.InstalledRuntime{}).ServeReadyConnector(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "AWG runtime stopped: "+err.Error())
		return 1
	}
	return 0
}

// runAWGRetireCommand retires only verified routes of a stopped instance during a locked installer migration or rollback.
func runAWGRetireCommand(id, number string, legacy bool) int {
	slot, err := strconv.Atoi(number)
	if os.Geteuid() != 0 || !awg.ValidConnectionID(id) || err != nil || strconv.Itoa(slot) != number || slot < 0 || slot >= awg.SlotCount || (legacy && slot != 0) {
		fmt.Fprintln(os.Stderr, "invalid AWG retirement request")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := platform.OfflineVerifier().RetirementOffline(ctx, id, legacy); err != nil {
		fmt.Fprintln(os.Stderr, "cannot confirm AWG retirement is offline")
		return 1
	}
	if err := awg.RetireStoppedConnector(ctx, id, slot, legacy); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// runAWGGuardCommand performs a read-only proof of both policy guards for a named slot before an installer starts the backend.
func runAWGGuardCommand(id, number string) int {
	slot, err := strconv.Atoi(number)
	if os.Geteuid() != 0 || err != nil || strconv.Itoa(slot) != number {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := awg.ConfirmConnectorGuards(ctx, id, slot); err != nil {
		return 1
	}
	return 0
}
