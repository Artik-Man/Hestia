package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// runBindingCommand applies one bounded JSON request or restores an interrupted installation.
// Exit codes 44 and 49 identify missing objects and compare-and-set conflicts to the HTTP caller.
func runBindingCommand(mode string, input io.Reader) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "binding helper requires root")
		return 1
	}
	limit := 2 * time.Minute
	if mode == "-watch-pending-binding" {
		// Allow the active writer to finish its deadline and rollback before taking the lock.
		limit = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	engine := binding.Installed()
	var err error
	switch mode {
	case "-apply-group-order":
		var change panelmodel.GroupOrderChange
		if decodeChange(input, 1<<20, &change) != nil {
			err = binding.ErrInvalidOrder
		} else {
			err = engine.ApplyOrder(ctx, change)
		}
	case "-recover-bindings":
		err = engine.Recover(ctx)
	case "-watch-pending-binding":
		err = engine.WatchPending(ctx)
	default:
		var change panelmodel.BindingChange
		change, err = readBindingChange(input)
		if err == nil {
			err = engine.Apply(ctx, change.ListID, change.ExpectedGroup, change.Group)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, binding.ErrInvalidOrder) {
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
