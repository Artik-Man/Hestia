package observer

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
)

// RunCLI runs the read-only observer, returning flag, configuration or execution errors to the caller.
func RunCLI(ctx context.Context, args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("hestia observe", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("config", "", "observer JSON configuration")
	rounds := flags.Int("rounds", 0, "number of probe rounds (zero runs until interrupted)")
	check := flags.Bool("check", false, "validate configuration without opening sockets")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *rounds < 0 || flags.NArg() != 0 {
		return fmt.Errorf("usage: hestia observe -config FILE [-rounds N] [-check]")
	}
	s, err := readSettings(*path)
	if err != nil {
		return err
	}
	if *check {
		return nil
	}
	return Run(ctx, s, *rounds, output)
}

// readSettings decodes at most one MiB of validated observer configuration.
func readSettings(path string) (Settings, error) {
	f, err := os.Open(path)
	if err != nil {
		return Settings{}, err
	}
	defer f.Close()
	const limit = 1 << 20
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return Settings{}, err
	}
	if len(data) > limit {
		return Settings{}, fmt.Errorf("observer config exceeds 1 MiB")
	}
	return Decode(data)
}
