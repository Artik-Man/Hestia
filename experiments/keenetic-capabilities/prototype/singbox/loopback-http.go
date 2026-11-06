// Command loopback-http serves one fixed response on a loopback-only TCP socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const responseBody = "hestia-sing-box-loopback-ok\n"

// main serves a fixed HTTP response only on 127.0.0.1 and exits after a bounded lifetime.
func main() {
	address := flag.String("listen", "127.0.0.1:18081", "loopback TCP address")
	duration := flag.Duration("duration", 45*time.Second, "maximum server lifetime")
	flag.Parse()
	if *duration <= 0 {
		fmt.Fprintln(os.Stderr, "duration must be positive")
		os.Exit(2)
	}
	if *address != "127.0.0.1:18081" {
		fmt.Fprintln(os.Stderr, "listen address must remain 127.0.0.1:18081")
		os.Exit(2)
	}
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	server := &http.Server{Handler: http.HandlerFunc(serveMarker)}
	finished := make(chan error, 1)
	go func() {
		finished <- server.Serve(listener)
	}()
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(shutdown)
	timer := time.NewTimer(*duration)
	defer timer.Stop()
	select {
	case <-shutdown:
	case <-timer.C:
	case err := <-finished:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// serveMarker returns the fixed marker for GET / and rejects every other request.
func serveMarker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(responseBody))
}
