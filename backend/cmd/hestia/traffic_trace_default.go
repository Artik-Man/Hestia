//go:build linux && arm64 && !android && !keenetic

package main

import (
	"errors"
	"io"
)

// runTrafficTraceCommand returns a clear error if called despite the feature being disabled in this build.
func runTrafficTraceCommand(io.Reader, io.Writer) error {
	return errors.New("traffic trace is only available in the Keenetic build")
}

// trafficTraceEnabled keeps the router-only capture command out of generic Linux builds.
func trafficTraceEnabled() bool { return false }
