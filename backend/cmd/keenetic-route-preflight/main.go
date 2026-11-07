//go:build linux && keenetic

// Command keenetic-route-preflight inspects one reserved AWG route slot without changing network state.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"time"

	"github.com/Artik-Man/Hestia/internal/network/keeneticroute"
	"github.com/Artik-Man/Hestia/internal/network/linuxroute"
)

// output contains one slot's reserved identifiers and the redacted result of read-only preflight.
type output struct {
	Slot     int    `json:"slot"`
	Table    string `json:"table"`
	Mark     string `json:"mark"`
	Priority string `json:"priority"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

// main inspects exactly one allowlisted slot and emits no route, rule, or interface listing.
func main() {
	slot := flag.Int("slot", 0, "reserved AWG slot to inspect (0-49)")
	timeout := flag.Duration("timeout", 20*time.Second, "maximum preflight duration")
	flag.Parse()
	if flag.NArg() != 0 || *slot < 0 || *slot >= 50 || *timeout <= 0 {
		fail("invalid_arguments")
	}
	policy, err := linuxroute.NewSlotPolicy(keeneticroute.ExecRouteRunner{}, *slot)
	if err != nil {
		fail("invalid_slot")
	}
	descriptor := policy.Descriptor()
	result := output{
		Slot:     *slot,
		Table:    descriptor.Table,
		Mark:     descriptor.Mark,
		Priority: descriptor.Priority,
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if err := policy.Preflight(ctx); err != nil {
		result.Status = "unavailable"
		result.Reason = reasonCode(err.Error())
	} else {
		result.Status = "available"
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail("output_failed")
	}
	if result.Status != "available" {
		os.Exit(1)
	}
}

// reasonCode maps fixed policy errors to stable summaries without exposing command output.
func reasonCode(reason string) string {
	switch reason {
	case "AWG routing priority is occupied":
		return "priority_occupied"
	case "AWG route table is occupied":
		return "table_occupied"
	case "AWG interface name is already occupied":
		return "device_occupied"
	case "cannot inspect routing rules":
		return "rules_unavailable"
	case "cannot inspect the AWG route table":
		return "routes_unavailable"
	case "cannot inspect network interfaces":
		return "links_unavailable"
	case "AWG route runner is unavailable":
		return "runner_unavailable"
	default:
		return "preflight_failed"
	}
}

// fail writes a stable error and exits without returning raw command output.
func fail(code string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "failed", "reason": code})
	os.Exit(2)
}
