//go:build linux && arm64 && !android

// Command hestia-panel serves the local gateway panel.
package main

import "github.com/Artik-Man/Hestia/internal/panel"

// main starts the gateway panel or exports its OpenAPI contract, according to the flags.
func main() {
	panel.Run()
}
