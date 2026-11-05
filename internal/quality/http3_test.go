package quality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// TestHTTP3PinnedExchange verifies a real UDP QUIC handshake, HTTP status and certificate validation on loopback.
func TestHTTP3PinnedExchange(t *testing.T) {
	verifyHTTP3Path(t, Path{DialContext: new(net.Dialer).DialContext})
}

// verifyHTTP3Path exercises a real QUIC service across either a directly connected or an authenticated SOCKS UDP path.
func verifyHTTP3Path(t *testing.T, path Path) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: certServer.TLS.Certificates},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.ProtoMajor == 3 && r.URL.RequestURI() == "/health?probe=1" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			http.Redirect(w, r, "/health?probe=1", http.StatusTemporaryRedirect)
		}),
	}
	go server.Serve(udp)
	defer server.Close()

	peer := udp.LocalAddr().(*net.UDPAddr)
	for _, tc := range []struct {
		name, host, path string
		want             outcome
	}{
		{"verified HTTP3", "example.com", "/health?probe=1", success},
		{"redirect is not followed", "example.com", "/redirect", failure},
		{"wrong TLS name", "other.invalid", "/health?probe=1", failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			socket, err := path.dial(ctx, "udp", peer.String())
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+tc.host+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &tls.Config{RootCAs: roots, ServerName: tc.host, NextProtos: []string{http3.NextProtoH3}}
			if got := exchangeHTTP3(req, socket, peer, cfg); got != tc.want {
				t.Fatalf("exchange returned %v, want %v", got, tc.want)
			}
		})
	}
}
