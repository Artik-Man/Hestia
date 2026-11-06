//go:build linux && arm64 && !android

package main

import (
	"os"
	"runtime"

	"github.com/Artik-Man/Hestia/internal/keeneticdiagnostics"
)

var buildVersion = "development"

// main delegates explicitly requested read-only inventory and exits with its CLI status.
func main() {
	os.Exit(keeneticdiagnostics.Run(os.Args[1:], os.Stdout, os.Stderr, os.DirFS("/"), runtime.GOOS, runtime.GOARCH, buildVersion))
}
