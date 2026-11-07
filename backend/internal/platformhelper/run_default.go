//go:build !keenetic

package platformhelper

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
)

// runInstalledHelper delegates the Linux helper through the existing noninteractive sudo boundary.
func runInstalledHelper(ctx context.Context, mode Mode, data []byte, output io.Writer, policy Cancellation) error {
	var command *exec.Cmd
	if policy == Transaction {
		if err := ctx.Err(); err != nil {
			return err
		}
		command = exec.Command("/usr/bin/sudo", "-n", "--", "/usr/local/bin/hestia", string(mode))
	} else {
		command = exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", "/usr/local/bin/hestia", string(mode))
	}
	command.Stdin = bytes.NewReader(data)
	command.Stderr = os.Stderr
	command.Stdout = output
	return command.Run()
}
