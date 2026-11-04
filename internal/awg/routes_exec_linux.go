//go:build linux

package awg

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

// ExecRouteRunner is the fixed-path iproute2 implementation for installed Linux gateways.
type ExecRouteRunner struct{}

// Run executes iproute2 with a short deadline and never includes command output in its returned error.
func (ExecRouteRunner) Run(parent context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).Output()
	if err != nil {
		return nil, errors.New("iproute2 command failed")
	}
	return output, nil
}
