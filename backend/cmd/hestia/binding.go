//go:build linux && arm64 && !android

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// runBindingCommand applies one bounded JSON request or restores an interrupted installation.
// Exit codes 44 and 49 identify missing objects and compare-and-set conflicts to the HTTP caller.
func runBindingCommand(mode string, input io.Reader, output io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "binding helper requires root")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), binding.CommandTimeout(mode))
	defer cancel()
	engine := binding.Installed()
	var err error
	switch mode {
	case "-enable-cpu-profiling", "-disable-cpu-profiling":
		err = engine.SetCPUProfiling(ctx, mode == "-enable-cpu-profiling")
	case "-migrate-country-map":
		err = engine.MigrateCountryMap(ctx)
	case "-apply-country-map":
		var change panelmodel.CountryMap
		if decodeChange(input, 128<<10, &change) != nil {
			err = binding.ErrInvalidCountryMap
		} else {
			var result panelmodel.CountryMap
			result, err = engine.ApplyCountryMap(ctx, change)
			if err == nil {
				err = json.NewEncoder(output).Encode(result)
			}
		}
	case "-create-domain-list":
		var values panelmodel.DomainListValues
		if decodeChange(input, 1<<20, &values) != nil {
			err = binding.ErrInvalidDomainList
		} else {
			var saved panelmodel.RuleList
			saved, err = engine.CreateDomainList(ctx, values)
			if err == nil {
				err = json.NewEncoder(output).Encode(saved)
			}
		}
	case "-update-domain-list":
		var change panelmodel.DomainListUpdate
		if decodeChange(input, 1<<20, &change) != nil {
			err = binding.ErrInvalidDomainList
		} else {
			var saved panelmodel.RuleList
			saved, err = engine.UpdateDomainList(ctx, change.Expected.ID, change)
			if err == nil {
				err = json.NewEncoder(output).Encode(saved)
			}
		}
	case "-delete-domain-list":
		var expected panelmodel.RuleList
		if decodeChange(input, 1<<20, &expected) != nil {
			err = binding.ErrInvalidDomainList
		} else {
			err = engine.DeleteDomainList(ctx, expected)
		}
	case "-delete-group":
		var group panelmodel.GroupDeleteCommand
		if decodeChange(input, 1024, &group) != nil {
			err = binding.ErrInvalidOrder
		} else {
			err = engine.DeleteGroup(ctx, group.ID)
		}
	case "-move-exit":
		var change panelmodel.ExitMoveCommand
		if decodeChange(input, 1024, &change) != nil {
			err = binding.ErrInvalidOrder
		} else {
			err = engine.MoveExit(ctx, change.ID, change.ExpectedGroup, change.Group, change.Priority)
		}
	case "-create-group":
		var group panelmodel.GroupCreateRequest
		if decodeChange(input, 1024, &group) != nil || (group.ID == nil) == (group.Name == nil) {
			err = binding.ErrInvalidOrder
		} else {
			var confirmed panelmodel.GroupIdentifier
			if group.ID != nil {
				confirmed.ID = *group.ID
				err = engine.CreateGroup(ctx, confirmed.ID)
			} else {
				confirmed.Name = *group.Name
				confirmed.ID, err = engine.CreateNamedGroup(ctx, confirmed.Name)
			}
			if err == nil {
				err = json.NewEncoder(output).Encode(confirmed)
			}
		}
	case "-set-connection-enabled":
		var request struct {
			ID      string `json:"id"`
			Enabled *bool  `json:"enabled"`
		}
		if decodeChange(input, 1024, &request) != nil || request.Enabled == nil {
			err = binding.ErrInvalidOrder
		} else {
			err = engine.SetConnectionEnabled(ctx, request.ID, *request.Enabled)
			if err == nil {
				err = json.NewEncoder(output).Encode(panelmodel.ConnectionEnabled{ID: request.ID, Enabled: *request.Enabled})
			}
		}
	case "-rename-group", "-rename-direct":
		var group panelmodel.GroupIdentifier
		if decodeChange(input, 1024, &group) != nil {
			err = binding.ErrInvalidOrder
		} else {
			if mode == "-rename-direct" {
				err = engine.RenameDirectConnection(group.ID, group.Name)
			} else {
				err = engine.RenameGroup(ctx, group.ID, group.Name)
			}
		}
	case "-apply-group-order":
		var change panelmodel.GroupOrderChange
		if decodeChange(input, 1<<20, &change) != nil {
			err = binding.ErrInvalidOrder
		} else {
			uplinkDevice := ""
			platformID := binding.PlatformUnderlayID()
			if platformID != "" && !orderContainsExit(change.Expected, platformID) && orderContainsExit(change.Groups, platformID) {
				uplinkDevice, _, err = keeneticUplink(ctx)
			}
			if err == nil {
				err = engine.ApplyOrderWithUplink(ctx, change, uplinkDevice)
			}
		}
	case "-recover-bindings":
		err = engine.Recover(ctx)
	case "-watch-pending-binding":
		err = engine.WatchPending(ctx)
	case "-enable-keenetic-ingress", "-disable-keenetic-ingress":
		err = runKeeneticIngress(ctx, mode == "-enable-keenetic-ingress")
	default:
		var change panelmodel.BindingChange
		change, err = readBindingChange(input)
		if err == nil {
			err = engine.Apply(ctx, change.ListID, change.ExpectedGroup, change.Group)
		}
	}
	if err != nil {
		writeBindingFailure(os.Stderr, binding.TransactionFailureStage(err), err)
		if errors.Is(err, binding.ErrInvalidCountryMap) || errors.Is(err, binding.ErrInvalidOrder) || errors.Is(err, binding.ErrInvalidDomainList) {
			return 42
		}
		if errors.Is(err, binding.ErrNotFound) {
			return 44
		}
		if errors.Is(err, binding.ErrConflict) {
			return 49
		}
		return 1
	}
	return 0
}

// writeBindingFailure prints a safe fixed transaction stage beside the bounded operation error.
func writeBindingFailure(output io.Writer, stage string, err error) {
	if stage != "" {
		fmt.Fprintf(output, "Hestia transaction failed at %s: %v\n", stage, err)
		return
	}
	fmt.Fprintln(output, err)
}

// orderContainsExit reports whether a requested group order contains the given exit ID.
func orderContainsExit(groups []panelmodel.OrderedGroup, id string) bool {
	for _, group := range groups {
		if slices.Contains(group.Exits, id) {
			return true
		}
	}
	return false
}

// readBindingChange accepts exactly one bounded request with all three strings present.
func readBindingChange(input io.Reader) (panelmodel.BindingChange, error) {
	var change panelmodel.BindingChange
	var fields struct {
		ListID        *string `json:"listId"`
		ExpectedGroup *string `json:"expectedGroup"`
		Group         *string `json:"group"`
	}
	if decodeChange(input, 8192, &fields) != nil || fields.ListID == nil || *fields.ListID == "" || fields.ExpectedGroup == nil || fields.Group == nil {
		return change, errors.New("invalid binding request")
	}
	return panelmodel.BindingChange{ListID: *fields.ListID, ExpectedGroup: *fields.ExpectedGroup, Group: *fields.Group}, nil
}

// decodeChange requires a single JSON object of bounded size and rejects unknown or trailing input.
func decodeChange(input io.Reader, limit int64, target any) error {
	data, err := io.ReadAll(io.LimitReader(input, limit+1))
	if err != nil || int64(len(data)) > limit {
		return errors.New("invalid routing request size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid routing request")
	}
	return nil
}
