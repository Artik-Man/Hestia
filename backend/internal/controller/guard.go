package controller

import (
	"context"

	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"slices"
	"time"

	"github.com/Artik-Man/Hestia/internal/routing"
)

// guardResult identifies the last confirmed outer gate and inner routes for this one-shot transition.
type guardResult struct {
	Group     string `json:"group"`
	Gate      string `json:"gate"`
	Normal    string `json:"normal,omitempty"`
	Exception string `json:"exception,omitempty"`
	Error     string `json:"error,omitempty"`
}

// RunGuardCLI applies one explicit availability snapshot using the group's preconfigured outer selector.
func RunGuardCLI(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("hestia guard", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "", "complete availability snapshot")
	group := flags.String("group", "", "two-exit group to reconcile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *group == "" || *config == "" {
		return fmt.Errorf("usage: hestia guard -config FILE -group GROUP")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("group guard requires Linux")
	}
	// Linux abstract sockets serialize cooperating invocations in the API's network namespace.
	lock, err := groupLock(*group)
	if err != nil {
		return fmt.Errorf("acquire group lock: %w", err)
	}
	defer lock.Close()
	data, err := os.ReadFile(*config)
	if err != nil {
		return err
	}
	cfg, err := CheckSnapshot(data)
	if err != nil {
		return err
	}
	client := newClient()
	defer client.CloseIdleConnections()
	result, applyErr := guard(ctx, client, localAPI, cfg, *group)
	if applyErr != nil {
		result.Error = applyErr.Error()
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return err
	}
	return applyErr
}

// guardedGroup checks that the three generated sing-box tags do not alias another configured group or exit.
func guardedGroup(cfg Config, id string) (routing.Group, error) {
	generated := []string{id + "-gate", id + "-dispatch", id + "-alt"}
	var selected routing.Group
	for _, group := range cfg.Groups {
		if slices.Contains(generated, group.ID) {
			return selected, fmt.Errorf("guard tag conflicts with group %q", group.ID)
		}
		for _, exit := range group.Exits {
			if slices.Contains(generated, exit) {
				return selected, fmt.Errorf("guard tag conflicts with exit %q", exit)
			}
		}
		if group.ID == id {
			selected = group
		}
	}
	if len(selected.Exits) != 2 {
		return selected, fmt.Errorf("guard requires one known group with exactly two exits")
	}
	return selected, nil
}

// guard closes the sole FI dispatch gate before changing inner routes and reopens it only after both confirmations.
func guard(parent context.Context, client *http.Client, base string, cfg Config, id string) (guardResult, error) {
	result := guardResult{Group: id, Gate: "unknown"}
	group, err := guardedGroup(cfg, id)
	if err != nil {
		return result, err
	}
	dispatch := id + "-dispatch"
	gate := routing.Group{ID: id + "-gate", Exits: []string{dispatch}}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	if _, err = reconcile(ctx, client, base, gate, deny); err != nil {
		return result, fmt.Errorf("initial deny barrier unconfirmed: %w", err)
	}
	result.Gate = deny
	normal, outcome := routing.SelectExit(group, cfg.Healthy)
	if outcome == routing.Block {
		return result, nil
	}
	alt := normal
	if cfg.Healthy[group.Exits[1]] {
		alt = group.Exits[1]
	}
	if _, err = reconcile(ctx, client, base, group, normal); err != nil {
		return result, fmt.Errorf("normal route while gate is deny: %w", err)
	}
	result.Normal = normal
	if _, err = reconcile(ctx, client, base, routing.Group{ID: id + "-alt", Exits: group.Exits}, alt); err != nil {
		return result, fmt.Errorf("exception route while gate is deny: %w", err)
	}
	result.Exception = alt
	if _, err = reconcile(ctx, client, base, gate, dispatch); err == nil {
		result.Gate = dispatch
		return result, nil
	}
	// A failed acknowledgement may follow a successful PUT. Reestablish the barrier independently of the original deadline.
	closeCtx, closeCancel := context.WithTimeout(context.WithoutCancel(parent), 3*time.Second)
	defer closeCancel()
	if _, closeErr := reconcile(closeCtx, client, base, gate, deny); closeErr != nil {
		result.Gate = "unknown"
		return result, fmt.Errorf("reopen not confirmed (%v); deny recovery also unconfirmed: %w", err, closeErr)
	}
	return result, fmt.Errorf("reopen not confirmed; deny restored: %w", err)
}
