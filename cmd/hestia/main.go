package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/observer"
)

// main selects snapshot validation, one-shot application, or continuous reconciliation.
// In watch mode SIGTERM and SIGINT cancel the polling loop.
func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-apply-group-order" || os.Args[1] == "-apply-binding" || os.Args[1] == "-recover-bindings" || os.Args[1] == "-watch-pending-binding") {
		os.Exit(runBindingCommand(os.Args[1], os.Stdin))
	}
	if len(os.Args) == 2 && os.Args[1] == "-awg-runtime" {
		os.Exit(runAWGRuntimeCommand())
	}
	if len(os.Args) == 2 && (os.Args[1] == "-awg-check" || os.Args[1] == "-awg-create" || os.Args[1] == "-awg-update" || os.Args[1] == "-awg-list" || os.Args[1] == "-awg-delete") {
		os.Exit(runAWGCommand(os.Args[1], os.Stdin, os.Stdout))
	}
	if len(os.Args) > 1 && (os.Args[1] == "observe" || os.Args[1] == "steer" || os.Args[1] == "guard" || os.Args[1] == "balance") {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		command := observer.RunCLI
		if os.Args[1] == "balance" {
			command = controller.RunBalanceCLI
		}
		if os.Args[1] == "guard" {
			command = controller.RunGuardCLI
		}
		if os.Args[1] == "steer" {
			command = observer.RunSteerCLI
		}
		if err := command(ctx, os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	config := flag.String("config", "", "JSON routing and availability snapshot")
	domain := flag.String("domain", "", "domain selecting the group (empty for direct IP)")
	check := flag.Bool("check", false, "validate snapshot without applying it")
	watch := flag.Bool("watch", false, "continuously reconcile group availability")
	interval := flag.Duration("interval", time.Second, "poll interval in watch mode")
	flag.Parse()
	if *config == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	var err error
	if *check {
		if *watch || *domain != "" {
			flag.Usage()
			os.Exit(2)
		}
		var data []byte
		data, err = os.ReadFile(*config)
		if err == nil {
			_, err = controller.CheckSnapshot(data)
		}
	} else if *watch {
		if *domain != "" || *interval <= 0 {
			flag.Usage()
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		output := json.NewEncoder(os.Stdout)
		err = controller.Watch(ctx, *config, *interval, func(result controller.Result) error { return output.Encode(result) }, func(err error) { fmt.Fprintln(os.Stderr, err) })
	} else {
		err = run(*config, *domain)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run applies the decision for domain from the snapshot at path. It writes the
// confirmed decision to standard output only after the selector check succeeds.
func run(path, domain string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cfg, err := controller.Decode(data)
	if err != nil {
		return err
	}
	result, err := controller.Apply(context.Background(), cfg, domain)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
