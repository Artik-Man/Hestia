//go:build linux && arm64 && !android && !keenetic

package main

import (
	"context"
	"errors"
)

// runKeeneticIngress rejects a router-only profile change in the standard Linux build.
func runKeeneticIngress(context.Context, bool) error {
	return errors.New("Keenetic ingress profile changes require a Keenetic build")
}
