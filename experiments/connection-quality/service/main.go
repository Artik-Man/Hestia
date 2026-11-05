// Command service serves a synthetic HTTPS and HTTP/3 target inside a disconnected lab network.
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// respond confirms the expected name, path and protocol; a per-transport fault file simulates a failed application.
func respond(w http.ResponseWriter, r *http.Request) {
	if r.Host != "quality.test:8443" || r.URL.Path != "/health" {
		http.NotFound(w, r)
		return
	}
	fault := "fail-https"
	if r.ProtoMajor == 3 {
		fault = "fail-http3"
	}
	if _, err := os.Stat(fault); !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// main serves the same test certificate and route over TCP and QUIC on port 8443.
func main() {
	h := http.HandlerFunc(respond)
	go func() {
		server := http.Server{Addr: ":8443", Handler: h, ReadHeaderTimeout: 3 * time.Second}
		log.Fatal(server.ListenAndServeTLS("../cert.pem", "../key.pem"))
	}()
	server := http3.Server{Addr: ":8443", Handler: h}
	log.Fatal(server.ListenAndServeTLS("../cert.pem", "../key.pem"))
}
