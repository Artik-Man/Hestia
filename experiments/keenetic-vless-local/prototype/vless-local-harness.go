// Command vless-local-harness checks loopback SOCKS TCP/UDP markers and VLESS UUID rejection.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	goodSOCKS = "127.0.0.1:19310"
	badSOCKS  = "127.0.0.1:19311"
	tcpTarget = "127.0.0.1:19312"
	udpTarget = "127.0.0.1:19313"
	tcpMarker = "HESTIA-VLESS-TCP-19312"
	udpMarker = "HESTIA-VLESS-UDP-19313"
)

var tcpCount atomic.Int64
var udpCount atomic.Int64

// main validates bounded runtime arguments and reports a nonzero exit on any failed criterion.
func main() {
	duration := flag.Duration("duration", 35*time.Second, "maximum endpoint lifetime")
	serverPID := flag.Int("server-pid", 0, "PID of the VLESS server")
	goodPID := flag.Int("good-client-pid", 0, "PID of the valid-UUID client")
	badPID := flag.Int("bad-client-pid", 0, "PID of the wrong-UUID client")
	flag.Parse()
	if *duration <= 0 || *duration > 45*time.Second || *serverPID <= 1 || *goodPID <= 1 || *badPID <= 1 {
		fmt.Fprintln(os.Stderr, "duration must be in (0,45s] and all process PIDs must be greater than 1")
		os.Exit(2)
	}
	if err := run(*duration, [3]int{*serverPID, *goodPID, *badPID}); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// run binds loopback echo endpoints and verifies direct controls, valid VLESS TCP/UDP, and wrong-UUID rejection.
func run(duration time.Duration, pids [3]int) error {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	tcpListener, err := net.Listen("tcp4", tcpTarget)
	if err != nil {
		return fmt.Errorf("bind TCP marker endpoint: %w", err)
	}
	defer tcpListener.Close()
	udpConn, err := net.ListenPacket("udp4", udpTarget)
	if err != nil {
		return fmt.Errorf("bind UDP marker endpoint: %w", err)
	}
	defer udpConn.Close()
	go serveTCP(ctx, tcpListener)
	go serveUDP(ctx, udpConn)
	logf("endpoints_ready tcp=%s udp=%s good_socks=%s wrong_socks=%s deadline=%s", tcpTarget, udpTarget, goodSOCKS, badSOCKS, time.Now().Add(duration).UTC().Format(time.RFC3339Nano))
	if err := directTCPCheck(ctx); err != nil {
		return fmt.Errorf("direct TCP positive control: %w", err)
	}
	if err := directUDPCheck(ctx); err != nil {
		return fmt.Errorf("direct UDP positive control: %w", err)
	}
	logf("direct_controls tcp_count=%d udp_count=%d result=markers_received", tcpCount.Load(), udpCount.Load())
	if err := socksTCPCheck(ctx, goodSOCKS, tcpMarker); err != nil {
		return fmt.Errorf("valid-UUID SOCKS TCP: %w", err)
	}
	if err := socksUDPCheck(ctx); err != nil {
		return fmt.Errorf("valid-UUID SOCKS UDP: %w", err)
	}
	if err := processesAlive(pids, "before_wrong_uuid"); err != nil {
		return err
	}
	before := tcpCount.Load()
	err = socksTCPRejectCheck(ctx)
	if err == nil {
		return errors.New("wrong UUID unexpectedly delivered the TCP marker")
	}
	if after := tcpCount.Load(); after != before {
		return fmt.Errorf("wrong UUID delivered data: TCP target count changed %d -> %d", before, after)
	}
	logf("wrong_uuid_probe result=rejected tcp_count_before=%d tcp_count_after=%d error=%q", before, tcpCount.Load(), err.Error())
	if err := processesAlive(pids, "after_wrong_uuid"); err != nil {
		return err
	}
	logf("final_counts tcp=%d udp=%d result=pass", tcpCount.Load(), udpCount.Load())
	return nil
}

// serveTCP returns one fixed marker per valid HTTP request and counts deliveries to the endpoint.
func serveTCP(ctx context.Context, listener net.Listener) {
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tcpCount.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, tcpMarker)
		logf("tcp_target received=%d marker=%s", tcpCount.Load(), tcpMarker)
	})}
	go func() { <-ctx.Done(); _ = server.Close() }()
	_ = server.Serve(listener)
}

// serveUDP counts each loopback datagram and replies with the fixed UDP marker.
func serveUDP(ctx context.Context, conn net.PacketConn) {
	go func() { <-ctx.Done(); _ = conn.Close() }()
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		udpCount.Add(1)
		_, _ = conn.WriteTo([]byte(udpMarker), addr)
		logf("udp_target received=%d payload=%q", udpCount.Load(), string(buf[:n]))
	}
}

// directTCPCheck proves the TCP endpoint is available without either SOCKS client.
func directTCPCheck(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+tcpTarget+"/", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: time.Until(deadline(ctx))}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if string(body) != tcpMarker {
		return fmt.Errorf("got %q, want %q", string(body), tcpMarker)
	}
	return nil
}

// directUDPCheck proves the UDP endpoint is available without either SOCKS client.
func directUDPCheck(ctx context.Context) error {
	conn, err := net.DialTimeout("udp4", udpTarget, remaining(ctx))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline(ctx))
	if _, err := io.WriteString(conn, "DIRECT-UDP-CONTROL"); err != nil {
		return err
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != udpMarker {
		return fmt.Errorf("got %q, want %q", string(buf[:n]), udpMarker)
	}
	return nil
}

// socksTCPCheck sends HTTP through the selected SOCKS listener and requires the exact marker.
func socksTCPCheck(ctx context.Context, proxy, marker string) error {
	conn, err := socksConnect(ctx, proxy, tcpTarget)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: loopback\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), marker) {
		return fmt.Errorf("response did not contain %q: %q", marker, string(body))
	}
	logf("vless_tcp result=marker_received tcp_count=%d", tcpCount.Load())
	return nil
}

// socksTCPRejectCheck requests the TCP marker through the wrong-UUID client and returns only when no marker arrives.
func socksTCPRejectCheck(ctx context.Context) error {
	conn, err := net.DialTimeout("tcp4", badSOCKS, remaining(ctx))
	if err != nil {
		return fmt.Errorf("wrong-UUID SOCKS listener unavailable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline(ctx))
	if err := socksNegotiate(conn); err != nil {
		return err
	}
	if err := writeConnectRequest(conn, tcpTarget); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("SOCKS CONNECT rejected before marker: %w", err)
	}
	if reply[1] != 0 {
		return fmt.Errorf("SOCKS CONNECT rejected with code %d", reply[1])
	}
	body, err := io.ReadAll(conn)
	if strings.Contains(string(body), tcpMarker) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("SOCKS tunnel closed without marker: %w", err)
	}
	return fmt.Errorf("SOCKS tunnel returned no marker (response %q)", string(body))
}

// socksUDPCheck performs a SOCKS5 UDP association through the valid-UUID VLESS client and requires its marker.
func socksUDPCheck(ctx context.Context) error {
	control, err := net.DialTimeout("tcp4", goodSOCKS, remaining(ctx))
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(deadline(ctx))
	if err := socksNegotiate(control); err != nil {
		return err
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(control, response); err != nil {
		return err
	}
	if response[1] != 0 || response[3] != 1 {
		return fmt.Errorf("SOCKS UDP ASSOCIATE reply=%v", response)
	}
	relay := &net.UDPAddr{IP: net.IP(response[4:8]), Port: int(binary.BigEndian.Uint16(response[8:10]))}
	udp, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		return err
	}
	defer udp.Close()
	_ = udp.SetDeadline(deadline(ctx))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], 19313)
	packet = append(packet, []byte("VLESS-UDP-MARKER-PROBE")...)
	if _, err := udp.Write(packet); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := udp.Read(buf)
	if err != nil {
		return err
	}
	if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || string(buf[10:n]) != udpMarker {
		return fmt.Errorf("invalid SOCKS UDP response %q", string(buf[:n]))
	}
	logf("vless_udp result=marker_received udp_count=%d", udpCount.Load())
	return nil
}

// socksConnect negotiates SOCKS5 and opens TCP to the supplied numeric loopback target.
func socksConnect(ctx context.Context, proxy, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", proxy, remaining(ctx))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(deadline(ctx))
	if err := socksNegotiate(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := writeConnectRequest(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if reply[1] != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS CONNECT reply code %d", reply[1])
	}
	return conn, nil
}

// socksNegotiate selects the no-authentication SOCKS5 method and checks the server response.
func socksNegotiate(conn net.Conn) error {
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return err
	}
	if method[0] != 5 || method[1] != 0 {
		return fmt.Errorf("SOCKS method negotiation failed: %v", method)
	}
	return nil
}

// writeConnectRequest encodes a numeric IPv4 SOCKS5 CONNECT request for a loopback destination.
func writeConnectRequest(conn net.Conn, target string) error {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fmt.Errorf("target is not a numeric IPv4 address: %s", host)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("invalid target port: %s", portText)
	}
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(request[8:], uint16(port))
	_, err = conn.Write(request)
	return err
}

// processesAlive checks each exact tracked PID before and after the wrong-UUID probe.
func processesAlive(pids [3]int, phase string) error {
	for i, pid := range pids {
		if err := syscall.Kill(pid, 0); err != nil {
			return fmt.Errorf("process phase=%s index=%d pid=%d is not alive: %w", phase, i, pid, err)
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return err
		}
		closeParen := strings.LastIndexByte(string(stat), ')')
		if closeParen < 0 {
			return fmt.Errorf("could not parse process stat for pid %d", pid)
		}
		fields := strings.Fields(string(stat[closeParen+1:]))
		if len(fields) == 0 || fields[0] == "Z" || fields[0] == "X" {
			return fmt.Errorf("process phase=%s index=%d pid=%d is not live", phase, i, pid)
		}
		logf("process_liveness phase=%s index=%d pid=%d state=%s", phase, i, pid, fields[0])
	}
	return nil
}

// logf writes one UTC-stamped evidence record to standard output.
func logf(format string, args ...any) {
	fmt.Printf("%s "+format+"\n", append([]any{time.Now().UTC().Format(time.RFC3339Nano)}, args...)...)
}

// deadline returns the context's deadline, or a short fallback for malformed contexts.
func deadline(ctx context.Context) time.Time {
	value, ok := ctx.Deadline()
	if !ok {
		return time.Now().Add(time.Second)
	}
	return value
}

// remaining returns positive time left in the bounded run context.
func remaining(ctx context.Context) time.Duration {
	value := time.Until(deadline(ctx))
	if value <= 0 {
		return time.Millisecond
	}
	return value
}
