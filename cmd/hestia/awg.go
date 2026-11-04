package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

const (
	awgStorePath = "/etc/hestia/awg"
	installLock  = "/run/hestia-install.lock"
)

// runAWGCommand accepts only fixed helper modes, runs with a bounded deadline, and writes sanitized output.
func runAWGCommand(mode string, input io.Reader, output io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "AWG helper requires root")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, err := awg.OpenStoreWithLock(awgStorePath, installLock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "AWG storage unavailable")
		return 1
	}
	manager := awg.NewManager(store, awg.InstalledRuntime{})
	switch mode {
	case "-awg-check":
		var request panelmodel.AWGCheckRequest
		if decodeChange(input, 40*1024, &request) != nil || request.Profile == "" {
			fmt.Fprintln(os.Stderr, "invalid AWG check request")
			return 42
		}
		if _, err := awg.Parse([]byte(request.Profile)); err != nil {
			fmt.Fprintln(os.Stderr, "invalid AWG profile")
			return 42
		}
		if err := manager.Check(ctx, []byte(request.Profile)); err != nil {
			fmt.Fprintln(os.Stderr, "AWG handshake was not confirmed")
			return 1
		}
		return encodeAWGResponse(output, panelmodel.AWGCheckResult{Status: "handshake_confirmed", Message: "AmneziaWG handshake подтверждён; групповой маршрут не изменён", RouteReady: false})
	case "-awg-create", "-awg-update":
		var request panelmodel.AWGSaveRequest
		if decodeChange(input, 40*1024, &request) != nil || request.ID == "" || request.Group == "" || request.Priority < 1 {
			fmt.Fprintln(os.Stderr, "invalid AWG save request")
			return 42
		}
		update := mode == "-awg-update"
		if err := binding.Installed().ApplyAWG(ctx, request, update); err != nil {
			fmt.Fprintln(os.Stderr, "AWG connection transaction was not committed")
			if errors.Is(err, binding.ErrNotFound) {
				return 44
			}
			if errors.Is(err, binding.ErrConflict) {
				return 49
			}
			if errors.Is(err, binding.ErrInvalidConnector) {
				return 42
			}
			return 1
		}
		connections, err := manager.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, "committed AWG metadata is unavailable")
			return 1
		}
		for _, connection := range connections {
			if connection.ID == request.ID {
				status := connection.Status
				if status == "ready" && !controller.AWGHeartbeatHealthy(connection.ID) {
					status = "error"
				}
				return encodeAWGResponse(output, panelmodel.AWGConnection{ID: connection.ID, Group: connection.Group, Priority: connection.Priority, Status: status, IPv6Blocked: connection.IPv6Blocked})
			}
		}
		return 1
	case "-awg-list":
		if decodeChange(input, 1024, &struct{}{}) != nil {
			fmt.Fprintln(os.Stderr, "invalid AWG list request")
			return 42
		}
		connections, err := manager.List()
		if err != nil {
			fmt.Fprintln(os.Stderr, "AWG list is unavailable")
			return 1
		}
		public := make([]panelmodel.AWGConnection, len(connections))
		for i, connection := range connections {
			status := connection.Status
			if status == "ready" && !controller.AWGHeartbeatHealthy(connection.ID) {
				status = "error"
			}
			public[i] = panelmodel.AWGConnection{ID: connection.ID, Group: connection.Group, Priority: connection.Priority, Status: status, IPv6Blocked: connection.IPv6Blocked}
		}
		return encodeAWGResponse(output, public)
	case "-awg-delete":
		var request panelmodel.AWGDeleteRequest
		if decodeChange(input, 1024, &request) != nil || request.ID == "" {
			fmt.Fprintln(os.Stderr, "invalid AWG delete request")
			return 42
		}
		if err := binding.Installed().DeleteAWG(ctx, request.ID); err != nil {
			fmt.Fprintln(os.Stderr, "AWG profile transaction was not committed")
			if errors.Is(err, binding.ErrNotFound) {
				return 44
			}
			return 1
		}
		return 0
	default:
		return 2
	}
}

// encodeAWGResponse writes one sanitized helper response and returns a stable helper exit status.
func encodeAWGResponse(output io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode AWG response")
		return 1
	}
	return 0
}
