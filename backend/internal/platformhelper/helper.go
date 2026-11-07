// Package platformhelper defines the installed privilege-boundary transport for typed application requests.
package platformhelper

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

// Mode identifies one allowlisted root-helper operation, never an executable or arbitrary argument list.
type Mode string

// Cancellation defines whether the caller may terminate the root helper after it starts.
type Cancellation uint8

const (
	Caller Cancellation = iota
	Transaction
)

// Transport executes a known helper request; callers own JSON types and public error mapping.
type Transport interface {
	Execute(context.Context, Mode, []byte, io.Writer, Cancellation) error
}

// Installed uses the selected platform's fixed helper boundary and executable.
type Installed struct{}

// validMode rejects unknown operations before starting a privileged process.
func validMode(mode Mode) bool {
	switch mode {
	case "-apply-binding", "-apply-group-order", "-apply-country-map", "-move-exit", "-create-group", "-rename-group", "-rename-direct", "-delete-group", "-create-domain-list", "-update-domain-list", "-delete-domain-list",
		"-awg-check", "-awg-create", "-awg-update", "-awg-list", "-awg-read", "-awg-delete", "-awg-underlays",
		"-physical-list", "-wifi-create", "-wifi-save", "-wifi-delete",
		"-hysteria2-list", "-hysteria2-read", "-hysteria2-create", "-hysteria2-update", "-hysteria2-delete":
		return true
	default:
		return false
	}
}

// Execute preserves stdin-only secrets, inherited stderr and each caller's historical cancellation policy.
func (Installed) Execute(ctx context.Context, mode Mode, data []byte, output io.Writer, policy Cancellation) error {
	if !validMode(mode) || (policy != Caller && policy != Transaction) {
		return errors.New("unsupported privileged helper operation")
	}
	return runInstalledHelper(ctx, mode, data, output, policy)
}

// ExitCode returns the helper's status, or -1 when no child exit status is available.
func ExitCode(err error) int {
	var failure *exec.ExitError
	if errors.As(err, &failure) {
		return failure.ExitCode()
	}
	return -1
}
