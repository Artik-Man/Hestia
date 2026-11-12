//go:build keenetic

package platformhelper

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

// runInstalledHelper executes only the allowlisted Hestia helper as root on the single-user Entware runtime.
func runInstalledHelper(ctx context.Context, mode Mode, data []byte, output io.Writer, policy Cancellation) error {
	if os.Geteuid() != 0 {
		return errors.New("Keenetic helper requires root")
	}
	var command *exec.Cmd
	if policy == Transaction {
		if err := ctx.Err(); err != nil {
			return err
		}
		command = exec.Command("/opt/bin/hestia", string(mode))
	} else {
		command = exec.CommandContext(ctx, "/opt/bin/hestia", string(mode))
	}
	command.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	command.Stdin = bytes.NewReader(data)
	command.Stderr = os.Stderr
	command.Stdout = output
	return command.Run()
}
