package awg

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
)

// outerPolicy derives a terminal rule for the daemon's outer mark; local loopback routing precedes it and no tunnel table follows it.
func outerPolicy(slot int) RoutePolicy {
	return RoutePolicy{runner: ExecRouteRunner{}, markValue: 0x51000 + slot, mark: fmt.Sprintf("0x%x", 0x51000+slot),
		priorityValue: 1100 + slot, priority: strconv.Itoa(1100 + slot), device: "lo"}
}

// outerBarrier changes only the recorded terminal rules for one validated slot. Installing refuses a pre-existing unowned rule.
func (p RoutePolicy) outerBarrier(ctx context.Context, id string, install bool) error {
	path := filepath.Join("/run/hestia-awg", "outer-rule."+id)
	manifest := p.manifest(id)
	owned, err := loadRouteManifest(path, manifest)
	if err != nil || (!install && !owned) {
		return err
	}
	present := map[string]bool{}
	for _, family := range []string{"-4", "-6"} {
		rules, err := p.runner.Run(ctx, family, "rule", "show")
		if err != nil {
			return errors.New("cannot inspect WireGuard outer guard")
		}
		found, err := p.inspectOwnedRule(string(rules))
		if err != nil {
			return err
		}
		if found && !owned {
			return errors.New("WireGuard outer guard priority is occupied")
		}
		present[family] = found
	}
	if install && !owned {
		if err := writeRouteManifest(path, manifest); err != nil {
			return err
		}
	}
	for _, family := range []string{"-4", "-6"} {
		if present[family] == install {
			continue
		}
		verb := "del"
		if install {
			verb = "add"
		}
		if _, err := p.runner.Run(ctx, family, "rule", verb, "priority", p.priority, "fwmark", p.mark+"/0xffffffff", "unreachable"); err != nil {
			return errors.New("cannot apply WireGuard outer guard")
		}
	}
	if !install {
		return removeRouteManifest(path)
	}
	return nil
}
