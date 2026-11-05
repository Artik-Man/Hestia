//go:build linux && arm64 && !android

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/physical"
)

// runPhysicalCommand accepts exact privilege-separated operations and exposes only public inventory or stable exit codes.
func runPhysicalCommand(mode string, input io.Reader, output io.Writer) int {
	if os.Geteuid() != 0 {
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	engine := binding.Installed()
	manager := physical.Manager{}
	var err error
	switch mode {
	case "-physical-list":
		if decodeChange(input, 128, &struct{}{}) != nil {
			return 42
		}
		var inventory panelmodel.PhysicalInventory
		inventory, err = engine.PhysicalConnections(ctx, manager)
		if err == nil {
			err = json.NewEncoder(output).Encode(inventory)
		}
	case "-wifi-create":
		var req panelmodel.WifiConnectionSettings
		if decodeChange(input, 2048, &req) != nil {
			return 42
		}
		err = engine.ChangeWifi(ctx, manager, "", &req)
	case "-wifi-save":
		var req panelmodel.WifiSaveCommand
		if decodeChange(input, 2048, &req) != nil || req.ID == "" {
			return 42
		}
		err = engine.ChangeWifi(ctx, manager, req.ID, &req.WifiConnectionSettings)
	case "-wifi-delete":
		var req panelmodel.AWGIDRequest
		if decodeChange(input, 256, &req) != nil || req.ID == "" {
			return 42
		}
		err = engine.ChangeWifi(ctx, manager, req.ID, nil)
	default:
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, binding.ErrInvalidOrder), errors.Is(err, physical.ErrInvalid):
		return 42
	case errors.Is(err, binding.ErrNotFound), errors.Is(err, physical.ErrNotFound):
		return 44
	case errors.Is(err, binding.ErrConflict), errors.Is(err, physical.ErrConflict):
		return 49
	default:
		return 1
	}
}
