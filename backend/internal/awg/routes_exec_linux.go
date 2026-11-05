//go:build linux

package awg

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// ExecRouteRunner is the fixed-path iproute2 implementation for installed Linux gateways.
type ExecRouteRunner struct{}

// Run executes iproute2 with a short deadline and never includes command output in its returned error.
func (ExecRouteRunner) Run(parent context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	return runIPRoute(ctx, "/usr/sbin/ip", args...)
}

// runIPRoute executes the selected binary and returns only routing data or a sanitized failure.
func runIPRoute(ctx context.Context, program string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		var status *exec.ExitError
		if ctx.Err() == nil && len(output) == 0 && errors.As(err, &status) && status.ExitCode() > 0 && missingPolicyTable(args, string(status.Stderr)) {
			return nil, nil
		}
		return nil, errors.New("iproute2 command failed")
	}
	return output, nil
}

// missingPolicyTable recognizes only an empty reserved-table dump diagnosed by iproute2 for the requested family.
func missingPolicyTable(args []string, stderr string) bool {
	if len(args) != 5 || !slices.Equal(args[1:4], []string{"route", "show", "table"}) {
		return false
	}
	table, err := strconv.Atoi(args[4])
	if err != nil || table < 202 || table >= 202+SlotCount || args[4] != strconv.Itoa(table) {
		return false
	}
	switch args[0] {
	case "-4":
		return strings.TrimSpace(stderr) == "Error: ipv4: FIB table does not exist.\nDump terminated"
	case "-6":
		return strings.TrimSpace(stderr) == "Error: ipv6: FIB table does not exist.\nDump terminated"
	default:
		return false
	}
}
