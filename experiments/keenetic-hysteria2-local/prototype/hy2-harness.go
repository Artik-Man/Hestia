// Command hy2-harness checks a local Hysteria 2 tunnel against loopback marker endpoints.
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
	socksAddress = "127.0.0.1:19330"
	tcpAddress   = "127.0.0.1:19335"
	udpAddress   = "127.0.0.1:19336"
	tcpMarker    = "HSTIA-HY2-TCP-19335"
	udpMarker    = "HSTIA-HY2-UDP-19336"
)

var tcpCount atomic.Int64
var udpCount atomic.Int64

// markerCounts records the TCP and UDP requests observed by the separate marker-server process.
type markerCounts struct {
	TCP int64
	UDP int64
}

// main selects an authentication-negative probe or valid TCP/UDP marker probes.
func main() {
	mode := flag.String("mode", "", "probe mode: bad-auth or positive")
	serverPID := flag.Int("server-pid", 0, "PID of the live Hysteria 2 server process")
	duration := flag.Duration("duration", 20*time.Second, "maximum probe lifetime")
	flag.Parse()
	if (*mode != "serve" && *mode != "bad-auth" && *mode != "positive") || (*mode != "serve" && *serverPID <= 1) || *duration <= 0 || *duration > 45*time.Second {
		fmt.Fprintln(os.Stderr, "mode must be serve|bad-auth|positive, probe server-pid > 1, duration in (0,45s]")
		os.Exit(2)
	}
	var err error
	if *mode == "bad-auth" {
		err = runBadAuth(*serverPID, *duration)
	} else if *mode == "positive" {
		err = runPositive(*serverPID, *duration)
	} else if *mode == "serve" {
		err = runServers(*duration)
	} else {
		fmt.Fprintln(os.Stderr, "unknown mode; expected serve, bad-auth, or positive")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// runServers binds only the two reserved loopback marker ports and shuts both listeners down at duration.
func runServers(duration time.Duration) error {
	tcpListener, err := net.Listen("tcp4", tcpAddress)
	if err != nil {
		return fmt.Errorf("listen TCP marker: %w", err)
	}
	defer tcpListener.Close()
	udpListener, err := net.ListenPacket("udp4", udpAddress)
	if err != nil {
		return fmt.Errorf("listen UDP marker: %w", err)
	}
	defer udpListener.Close()
	server := &http.Server{Handler: http.HandlerFunc(serveTCP)}
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(tcpListener) }()
	go serveUDP(udpListener)
	logf("endpoints_ready tcp=%s udp=%s lifetime=%s", tcpAddress, udpAddress, duration)
	time.Sleep(duration)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown TCP marker: %w", err)
	}
	if err := udpListener.Close(); err != nil {
		return fmt.Errorf("close UDP marker: %w", err)
	}
	if err := <-serveError; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve TCP marker: %w", err)
	}
	logf("endpoints_stopped tcp_count=%d udp_count=%d", tcpCount.Load(), udpCount.Load())
	return nil
}

// runBadAuth confirms the endpoint and server remain live while a wrong-password SOCKS request is rejected.
func runBadAuth(serverPID int, duration time.Duration) error {
	if err := directTCPCheck(); err != nil {
		return fmt.Errorf("direct endpoint control: %w", err)
	}
	before, err := targetCounts()
	if err != nil {
		return fmt.Errorf("read marker counters before negative probe: %w", err)
	}
	if err := processAlive(serverPID); err != nil {
		return fmt.Errorf("server not live before negative probe: %w", err)
	}
	logf("negative_precondition endpoint=live target_tcp=%d target_udp=%d server_pid=%d server=live", before.TCP, before.UDP, serverPID)
	err = socksTCPAttempt(time.Now().Add(duration), 2*time.Second)
	if err == nil {
		return errors.New("wrong-password request unexpectedly returned the target marker")
	}
	after, countErr := targetCounts()
	if countErr != nil {
		return fmt.Errorf("read marker counters after negative probe: %w", countErr)
	}
	if after != before {
		return fmt.Errorf("endpoint counters changed during wrong-password request: before=%+v after=%+v", before, after)
	}
	if err := processAlive(serverPID); err != nil {
		return fmt.Errorf("server not live after negative probe: %w", err)
	}
	logf("negative_result result=rejected target_marker=absent endpoint_counts_before=%+v after=%+v server_pid=%d server=live probe_error=%q", before, after, serverPID, err.Error())
	return nil
}

// runPositive validates TCP and UDP marker delivery through the authenticated Hysteria 2 client.
func runPositive(serverPID int, duration time.Duration) error {
	deadline := time.Now().Add(duration)
	if err := processAlive(serverPID); err != nil {
		return fmt.Errorf("server not live before positive probes: %w", err)
	}
	before, err := targetCounts()
	if err != nil {
		return fmt.Errorf("read marker counters before positive probes: %w", err)
	}
	if err := socksTCPAttempt(deadline, 4*time.Second); err != nil {
		return fmt.Errorf("SOCKS TCP marker: %w", err)
	}
	if err := socksUDPCheck(deadline); err != nil {
		return fmt.Errorf("SOCKS UDP marker: %w", err)
	}
	after, err := targetCounts()
	if err != nil {
		return fmt.Errorf("read marker counters after positive probes: %w", err)
	}
	if after.TCP != before.TCP+1 || after.UDP != before.UDP+1 {
		return fmt.Errorf("unexpected marker counter changes: before=%+v after=%+v", before, after)
	}
	if err := processAlive(serverPID); err != nil {
		return fmt.Errorf("server not live after positive probes: %w", err)
	}
	logf("positive_result endpoint_counts_before=%+v after=%+v server_pid=%d server=live", before, after, serverPID)
	return nil
}

// processAlive confirms that the exact observed server PID exists and is not a zombie.
func processAlive(pid int) error {
	if err := syscall.Kill(pid, 0); err != nil {
		return err
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return err
	}
	closeParen := strings.LastIndexByte(string(stat), ')')
	if closeParen < 0 {
		return errors.New("could not parse process state")
	}
	fields := strings.Fields(string(stat[closeParen+1:]))
	if len(fields) == 0 || fields[0] == "Z" || fields[0] == "X" {
		return fmt.Errorf("process is not live: state %q", fields)
	}
	return nil
}

// serveTCP accepts loopback HTTP marker checks and counts each delivered request.
func serveTCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/counters" {
		_, _ = fmt.Fprintf(w, "tcp=%d udp=%d", tcpCount.Load(), udpCount.Load())
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tcpCount.Add(1)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, tcpMarker)
	logf("tcp_target address=%s count=%d", tcpAddress, tcpCount.Load())
}

// targetCounts reads both counters from the separate loopback marker process without incrementing either.
func targetCounts() (markerCounts, error) {
	conn, err := net.DialTimeout("tcp4", tcpAddress, time.Second)
	if err != nil {
		return markerCounts{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "GET /counters HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		return markerCounts{}, err
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		return markerCounts{}, err
	}
	body := string(response)
	marker := strings.LastIndex(body, "\r\n\r\n")
	if marker < 0 {
		return markerCounts{}, fmt.Errorf("counter response has no HTTP body: %q", body)
	}
	var counts markerCounts
	if _, err := fmt.Sscanf(body[marker+4:], "tcp=%d udp=%d", &counts.TCP, &counts.UDP); err != nil {
		return markerCounts{}, fmt.Errorf("parse marker counters: %w", err)
	}
	return counts, nil
}

// serveUDP returns the fixed marker only to packets received on the owned loopback endpoint.
func serveUDP(conn net.PacketConn) {
	buffer := make([]byte, 512)
	for {
		n, address, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		udpCount.Add(1)
		_, _ = conn.WriteTo([]byte(udpMarker), address)
		logf("udp_target address=%s received=%q count=%d", conn.LocalAddr(), string(buffer[:n]), udpCount.Load())
	}
}

// directTCPCheck proves the marker endpoint is reachable outside the proxy before a negative auth attempt.
func directTCPCheck() error {
	conn, err := net.DialTimeout("tcp4", tcpAddress, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		return err
	}
	response, err := io.ReadAll(conn)
	if err != nil || !strings.Contains(string(response), tcpMarker) {
		return fmt.Errorf("direct marker absent response=%q err=%v", response, err)
	}
	logf("direct_control result=marker_received tcp_count=%d", tcpCount.Load())
	return nil
}

// socksTCPAttempt sends a marker request through SOCKS and returns an error unless the marker arrives.
func socksTCPAttempt(deadline time.Time, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp4", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer conn.Close()
	probeDeadline := time.Now().Add(timeout)
	if probeDeadline.After(deadline) {
		probeDeadline = deadline
	}
	_ = conn.SetDeadline(probeDeadline)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[0] != 5 || method[1] != 0 {
		return fmt.Errorf("SOCKS method negotiation failed reply=%v err=%v", method, err)
	}
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], 19335)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0 {
		return fmt.Errorf("SOCKS CONNECT rejected reply=%d", response[1])
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !strings.Contains(string(body), tcpMarker) {
		return fmt.Errorf("TCP marker absent response=%q", body)
	}
	logf("socks_tcp result=marker_received target_count=%d", tcpCount.Load())
	return nil
}

// socksUDPCheck sends and validates the loopback UDP marker through a SOCKS5 UDP association.
func socksUDPCheck(deadline time.Time) error {
	control, err := net.DialTimeout("tcp4", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(deadline)
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(control, method); err != nil || method[0] != 5 || method[1] != 0 {
		return fmt.Errorf("SOCKS method negotiation failed reply=%v err=%v", method, err)
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
	probeDeadline := time.Now().Add(4 * time.Second)
	if probeDeadline.After(deadline) {
		probeDeadline = deadline
	}
	_ = udp.SetDeadline(probeDeadline)
	frame := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(frame[8:], 19336)
	frame = append(frame, []byte("HY2-UDP-PROBE")...)
	if _, err := udp.Write(frame); err != nil {
		return err
	}
	buffer := make([]byte, 512)
	n, err := udp.Read(buffer)
	if err != nil {
		return err
	}
	if n < 10 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 1 || string(buffer[10:n]) != udpMarker {
		return fmt.Errorf("unexpected SOCKS UDP response %v", buffer[:n])
	}
	logf("socks_udp result=marker_received target_count=%d", udpCount.Load())
	return nil
}

// logf writes a timestamped line suitable for capturing as an immutable run transcript.
func logf(format string, args ...any) {
	values := append([]any{time.Now().UTC().Format(time.RFC3339Nano)}, args...)
	fmt.Fprintf(os.Stdout, "%s "+format+"\n", values...)
}
