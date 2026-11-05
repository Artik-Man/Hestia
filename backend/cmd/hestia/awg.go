//go:build linux && arm64 && !android

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
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

// runAWGCommand accepts only fixed helper modes, runs with a bounded deadline, and returns stored secrets only in explicit single-profile reads.
func runAWGCommand(mode string, input io.Reader, output io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "AWG helper requires root")
		return 1
	}
	timeout := 2 * time.Minute
	if mode == "-awg-create" || mode == "-awg-update" {
		timeout = binding.AWGActivationLimit
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if mode == "-awg-underlays" {
		if decodeChange(input, 1024, &struct{}{}) != nil {
			return 42
		}
		result, err := binding.Installed().UnderlayCandidates()
		if errors.Is(err, binding.ErrConflict) {
			return 49
		}
		if err != nil {
			return 1
		}
		return encodeAWGResponse(output, result)
	}
	if mode == "-awg-read" {
		var request panelmodel.AWGIDRequest
		if decodeChange(input, 1024, &request) != nil || request.ID == "" {
			return 42
		}
		profile, err := binding.Installed().ReadAWGProfile(request.ID)
		if errors.Is(err, binding.ErrNotFound) {
			return 44
		}
		if errors.Is(err, binding.ErrConflict) {
			return 49
		}
		if err != nil {
			return 1
		}
		return encodeAWGResponse(output, profile)
	}
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
		if decodeChange(input, 40*1024, &request) != nil || request.ID == "" || (mode == "-awg-create" && request.Group == "") || request.Priority < 0 {
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
				return encodeAWGResponse(output, publicAWGConnection(connection))
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
			public[i] = publicAWGConnection(connection)
		}
		return encodeAWGResponse(output, public)
	case "-awg-delete":
		var request panelmodel.AWGIDRequest
		if decodeChange(input, 1024, &request) != nil || request.ID == "" {
			fmt.Fprintln(os.Stderr, "invalid AWG delete request")
			return 42
		}
		if err := binding.Installed().DeleteAWG(ctx, request.ID); err != nil {
			fmt.Fprintln(os.Stderr, "AWG profile transaction was not committed")
			if errors.Is(err, binding.ErrNotFound) {
				return 44
			}
			if errors.Is(err, binding.ErrConflict) {
				return 49
			}
			return 1
		}
		return 0
	default:
		return 2
	}
}

// encodeAWGResponse writes one typed helper response and returns a stable helper exit status.
func encodeAWGResponse(output io.Writer, value any) int {
	if err := json.NewEncoder(output).Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode AWG response")
		return 1
	}
	return 0
}

// publicAWGConnection joins persisted preference with verified runtime health without exposing keys or stale transport choices.
func publicAWGConnection(c awg.Metadata) panelmodel.AWGConnection {
	status, active := c.Status, ""
	if status == "ready" {
		selected, ok := controller.AWGTransportHealth(c.ID)
		if !ok || (len(c.Underlays) > 0 && !slices.Contains(c.Underlays, selected)) || (len(c.Underlays) == 0 && selected != "") {
			status = "error"
		} else {
			active = selected
		}
	}
	return panelmodel.AWGConnection{ID: c.ID, Group: c.Group, Priority: c.Priority, Status: status, IPv6Blocked: c.IPv6Blocked, Underlays: c.Underlays, ActiveUnderlay: active}
}
