//go:build linux && arm64 && !android

// This standalone probe tests only whether the calling thread can enter a new
// network namespace. It never creates links, routes, sockets, or child processes.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// probeResult describes one namespace syscall without inferring routing support.
type probeResult struct {
	SchemaVersion int    `json:"schema_version"`
	Operation     string `json:"operation"`
	Status        string `json:"status"`
	Errno         int    `json:"errno,omitempty"`
	Error         string `json:"error,omitempty"`
	HostChanges   bool   `json:"host_network_changes"`
}

// main requires explicit opt-in, locks the executing thread, attempts one
// CLONE_NEWNET operation and exits the whole process without reusing that thread.
// Exit 0 means a valid observation, including syscall rejection; exit 2 means
// invalid arguments, and exit 1 means the JSON observation could not be written.
func main() {
	if len(os.Args) == 1 || len(os.Args) == 2 && os.Args[1] == "--help" {
		fmt.Println("Usage: netns-probe --probe-netns\nOne isolated namespace syscall; no network configuration changes.")
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--probe-netns" {
		fmt.Fprintln(os.Stderr, "Use --help or --probe-netns")
		os.Exit(2)
	}
	runtime.LockOSThread()
	result := probeResult{SchemaVersion: 1, Operation: "unshare(CLONE_NEWNET)", Status: "created_and_process_exiting"}
	if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
		result.Status = "rejected"
		result.Error = err.Error()
		if errno, ok := err.(syscall.Errno); ok {
			result.Errno = int(errno)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot write probe result")
		os.Exit(1)
	}
	os.Exit(0)
}
