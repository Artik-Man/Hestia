// Command hestia-cli provides standalone administrative and research utilities for Hestia.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/hestiacli"
)

// main dispatches the requested hestia-cli subcommand and reports failures to stderr.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hestia-cli:", err)
		os.Exit(1)
	}
}

// run parses the command and starts the selected standalone utility.
func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printUsage(os.Stdout)
		return nil
	}
	if args[0] == "dns-forwarder" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return hestiacli.RunDNSForwarder(ctx, args[1:], os.Stdout, os.Stderr)
	}
	if args[0] != "serve" {
		return fmt.Errorf("unknown command %q; use 'hestia-cli help'", args[0])
	}
	return runFileServer(args[1:])
}

// runFileServer parses file-server settings and serves authenticated upload and download endpoints until shutdown.
func runFileServer(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: hestia-cli serve -upload-dir DIR -download-dir DIR -token-file FILE [-listen :8081]")
	}
	address := flags.String("listen", ":8081", "HTTP listen address")
	uploadDir := flags.String("upload-dir", "", "existing directory for uploaded files")
	downloadDir := flags.String("download-dir", "", "existing directory for downloadable files")
	tokenFile := flags.String("token-file", "", "private bearer token file with no group/other permissions")
	maxUpload := flags.Int64("max-upload-bytes", 128<<20, "maximum request body size in bytes (hard maximum 128 MiB)")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve accepts flags only")
	}
	if *uploadDir == "" || *downloadDir == "" || *tokenFile == "" {
		return errors.New("serve requires -upload-dir, -download-dir, and -token-file")
	}
	files, err := hestiacli.NewFileServer(hestiacli.FileServerConfig{
		Address:        *address,
		UploadRoot:     *uploadDir,
		DownloadRoot:   *downloadDir,
		TokenFile:      *tokenFile,
		MaxUploadBytes: *maxUpload,
	})
	if err != nil {
		return err
	}
	defer files.Close()
	server := &http.Server{
		Addr:              *address,
		Handler:           files.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServe() }()
	log.Printf("hestia-cli file server listening on %s", *address)
	select {
	case err := <-served:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdown); err != nil {
		_ = server.Close()
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// printUsage writes the supported command syntax to the selected output.
func printUsage(writer *os.File) {
	fmt.Fprintln(writer, `Usage:
  hestia-cli serve -upload-dir DIR -download-dir DIR -token-file FILE [-listen :8081]
  hestia-cli dns-forwarder enable -interface NAME [-interface NAME ...]
  hestia-cli dns-forwarder status
  hestia-cli dns-forwarder disable

The server exposes authenticated file upload and download endpoints. It does not execute uploaded files.
The DNS-forwarder command manages the Hestia DNS profile on Keenetic.`)
}
