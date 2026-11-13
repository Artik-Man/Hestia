//go:build linux && arm64 && !android

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/dnsservice"
	"github.com/Artik-Man/Hestia/internal/observer"
	"github.com/Artik-Man/Hestia/internal/platform"
)

// main selects snapshot validation, one-shot application, or continuous reconciliation.
// In watch mode SIGTERM and SIGINT cancel the polling loop.
func main() {
	if len(os.Args) == 2 && os.Args[1] == "-service-supervisor" {
		diagnostics, err := openSupervisorDiagnostics()
		if err == nil {
			defer diagnostics.Close()
			os.Stderr = diagnostics
			log.SetOutput(diagnostics)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := platform.RunSupervisor(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if trafficTraceEnabled() && len(os.Args) == 2 && os.Args[1] == "-traffic-trace" {
		if err := runTrafficTraceCommand(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-check-idle" {
		if err := platform.CheckManagedProcessesStopped(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-service-check-pid" {
		pid, err := strconv.Atoi(os.Args[2])
		if err != nil || platform.CheckSupervisorProcess(pid) != nil {
			fmt.Fprintln(os.Stderr, "Hestia supervisor PID is not verified")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-supervisor-ready" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := platform.SupervisorReady(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "Hestia supervisor is not ready")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-reconcile-ingress" {
		ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
		defer cancel()
		if err := platform.ReconcileIngress(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "Keenetic ingress reconciliation failed")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-ingress-quiesce" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := platform.QuiesceIngress(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "Keenetic ingress reconciliation is still active")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-opkgtun-ensure" {
		if err := platform.EnsureOpkgTun(); err != nil {
			fmt.Fprintln(os.Stderr, "Hestia OpkgTun could not be prepared")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "-service-opkgtun-remove" {
		if err := platform.RemoveOpkgTun(); err != nil {
			fmt.Fprintf(os.Stderr, "Hestia OpkgTun could not be removed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "dns" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := dnsservice.Run(ctx, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 {
		switch os.Args[1] {
		case "-hysteria2-read", "-hysteria2-list", "-hysteria2-create", "-hysteria2-update", "-hysteria2-delete":
			os.Exit(runHysteria2Command(os.Args[1], os.Stdin, os.Stdout))
		case "-physical-list", "-wifi-create", "-wifi-save", "-wifi-delete":
			os.Exit(runPhysicalCommand(os.Args[1], os.Stdin, os.Stdout))
		}
	}
	if len(os.Args) == 2 && (os.Args[1] == "-apply-country-map" || os.Args[1] == "-migrate-country-map" || os.Args[1] == "-delete-domain-list" || os.Args[1] == "-create-domain-list" || os.Args[1] == "-update-domain-list" || os.Args[1] == "-delete-group" || os.Args[1] == "-move-exit" || os.Args[1] == "-create-group" || os.Args[1] == "-rename-group" || os.Args[1] == "-rename-direct" || os.Args[1] == "-set-connection-enabled" || os.Args[1] == "-apply-group-order" || os.Args[1] == "-apply-binding" || os.Args[1] == "-recover-bindings" || os.Args[1] == "-watch-pending-binding" || os.Args[1] == "-enable-keenetic-ingress" || os.Args[1] == "-disable-keenetic-ingress" || os.Args[1] == "-enable-cpu-profiling" || os.Args[1] == "-disable-cpu-profiling") {
		os.Exit(runBindingCommand(os.Args[1], os.Stdin, os.Stdout))
	}
	if len(os.Args) == 4 && os.Args[1] == "-awg-guard" {
		os.Exit(runAWGGuardCommand(os.Args[2], os.Args[3]))
	}
	if len(os.Args) == 4 && (os.Args[1] == "-awg-retire" || os.Args[1] == "-awg-retire-legacy") {
		os.Exit(runAWGRetireCommand(os.Args[2], os.Args[3], os.Args[1] == "-awg-retire-legacy"))
	}
	if (len(os.Args) == 2 || len(os.Args) == 3) && os.Args[1] == "-awg-runtime" {
		id := ""
		if len(os.Args) == 3 {
			id = os.Args[2]
		}
		os.Exit(runAWGRuntimeCommand(id))
	}
	if len(os.Args) == 2 && (os.Args[1] == "-awg-check" || os.Args[1] == "-awg-create" || os.Args[1] == "-awg-update" || os.Args[1] == "-awg-list" || os.Args[1] == "-awg-underlays" || os.Args[1] == "-awg-read" || os.Args[1] == "-awg-delete") {
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
	quality := flag.Bool("quality", false, "measure connection quality and rank available exits in watch mode")
	interval := flag.Duration("interval", time.Second, "poll interval in watch mode")
	flag.Parse()
	if *config == "" || flag.NArg() != 0 || (*quality && !*watch) {
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
		err = controller.Watch(ctx, *config, *interval, *quality, func(result controller.Result) error { return output.Encode(result) }, func(err error) { fmt.Fprintln(os.Stderr, err) })
	} else {
		err = run(*config, *domain)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// openSupervisorDiagnostics appends supervisor startup and runtime errors to a root-only regular file.
func openSupervisorDiagnostics() (*os.File, error) {
	path := "/opt/var/run/hestia/supervisor.log"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("supervisor diagnostics path is not a regular file")
	}
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("cannot secure supervisor diagnostics file")
	}
	return file, nil
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
