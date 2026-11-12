package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// main performs one bounded HTTP/3 request to a pinned Google IPv4 address.
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	peer := &net.UDPAddr{IP: net.ParseIP("142.250.120.100").To4(), Port: 443}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 49690})
	if err != nil {
		fmt.Printf("udp_socket_error=%v\n", err)
		return
	}
	defer socket.Close()
	transport := &quic.Transport{Conn: socket}
	defer transport.Close()
	tlsConfig := &tls.Config{ServerName: "google.com", MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}}
	conn, err := transport.Dial(ctx, peer, tlsConfig, &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 8 * time.Second})
	if err != nil {
		fmt.Printf("quic_error=%v peer=%s\n", err, peer)
		return
	}
	defer conn.CloseWithError(0, "probe complete")
	client := (&http3.Transport{MaxResponseHeaderBytes: 16384, DisableCompression: true}).NewClientConn(conn)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://google.com/", nil)
	if err != nil {
		fmt.Printf("request_error=%v\n", err)
		return
	}
	response, err := client.RoundTrip(request)
	if err != nil {
		fmt.Printf("http3_error=%v\n", err)
		return
	}
	defer response.Body.Close()
	fmt.Printf("http_status=%d protocol=%s peer=%s\n", response.StatusCode, response.Proto, peer)
}
