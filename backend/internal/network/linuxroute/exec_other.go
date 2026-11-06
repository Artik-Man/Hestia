//go:build !linux

package linuxroute

import (
	"context"
	"errors"
)

// ExecRouteRunner is an unavailable platform placeholder for Linux-only policy routing.
type ExecRouteRunner struct{}

// Run fails closed on non-Linux hosts and performs no system command.
func (ExecRouteRunner) Run(context.Context, ...string) ([]byte, error) {
	return nil, errors.New("AWG policy routing requires Linux")
}
