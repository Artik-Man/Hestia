// Command udp-block-harness probes local SOCKS TCP/UDP behavior against loopback markers.
package main

import (
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
	socksAddress = "127.0.0.1:19180"
	allowAddress = "127.0.0.1:19182"
	denyAddress  = "127.0.0.2:19183"
	tcpAddress   = "127.0.0.1:19181"
	allowMarker  = "HSTIA-UDP-ALLOW-19182"
	denyMarker   = "HSTIA-UDP-DENY-WITNESS-19183"
)

var allowCount atomic.Int64
var denyCount atomic.Int64
var tcpCount atomic.Int64

// main starts loopback marker endpoints, verifies direct reachability, then probes SOCKS TCP/UDP.
// It exits nonzero unless positive controls succeed and the SOCKS request to 127.0.0.2 is dropped.
func main() {
	duration := flag.Duration("duration", 35*time.Second, "maximum endpoint lifetime")
	daemonPID := flag.Int("daemon-pid", 0, "PID of the sing-box process under observation")
	flag.Parse()
	if *duration <= 0 || *duration > 45*time.Second || *daemonPID <= 1 {
		fmt.Fprintln(os.Stderr, "duration must be in (0,45s] and daemon-pid must be greater than 1")
		os.Exit(2)
	}
	if err := run(*duration, *daemonPID); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// run binds only the reserved loopback endpoints, performs the checks within duration, and shuts down.
func run(duration time.Duration, daemonPID int) error {
	allowConn, err := net.ListenPacket("udp4", allowAddress)
	if err != nil {
		return fmt.Errorf("bind allowed UDP target: %w", err)
	}
	defer allowConn.Close()
	denyConn, err := net.ListenPacket("udp4", denyAddress)
	if err != nil {
		return fmt.Errorf("bind deny witness: %w", err)
	}
	defer denyConn.Close()
	tcpListener, err := net.Listen("tcp4", tcpAddress)
	if err != nil {
		return fmt.Errorf("bind TCP marker target: %w", err)
	}
	defer tcpListener.Close()

	go serveUDP(allowConn, allowMarker, &allowCount)
	go serveUDP(denyConn, denyMarker, &denyCount)
	server := &http.Server{Handler: http.HandlerFunc(serveTCPMarker)}
	go func() { _ = server.Serve(tcpListener) }()
	deadline := time.Now().Add(duration)
	logf("endpoints_ready tcp=%s allow_udp=%s deny_witness=%s socks=%s deadline=%s", tcpAddress, allowAddress, denyAddress, socksAddress, deadline.UTC().Format(time.RFC3339Nano))

	if err := directUDPCheck(denyAddress, denyMarker); err != nil {
		return fmt.Errorf("direct positive control: %w", err)
	}
	logf("direct_positive_control deny_target_count=%d result=marker_received", denyCount.Load())
	if err := socksTCPCheck(deadline); err != nil {
		return fmt.Errorf("SOCKS TCP positive check: %w", err)
	}
	if err := socksUDPCheck(allowAddress, allowMarker, 1800*time.Millisecond, deadline); err != nil {
		return fmt.Errorf("SOCKS UDP allow check: %w", err)
	}
	if err := processAlive(daemonPID); err != nil {
		return fmt.Errorf("sing-box was not alive before blocked probe: %w", err)
	}
	logf("singbox_liveness phase=before_block pid=%d result=alive", daemonPID)
	logf("udp_counts_before_block allow=%d deny_witness=%d", allowCount.Load(), denyCount.Load())
	before := denyCount.Load()
	err = socksUDPCheck(denyAddress, denyMarker, 1200*time.Millisecond, deadline)
	if err == nil {
		return errors.New("SOCKS UDP request to deny witness unexpectedly returned its marker")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !isTimeout(err) {
		return fmt.Errorf("blocked probe failed without an expected timeout: %w", err)
	}
	after := denyCount.Load()
	logf("blocked_probe result=timeout target_counter_before=%d target_counter_after=%d error=%q", before, after, err.Error())
	if after != before {
		return fmt.Errorf("deny witness received blocked request: counter changed from %d to %d", before, after)
	}
	if err := processAlive(daemonPID); err != nil {
		return fmt.Errorf("sing-box was not alive after blocked probe: %w", err)
	}
	logf("singbox_liveness phase=after_block pid=%d result=alive", daemonPID)
	logf("final_counts allow_udp=%d deny_witness=%d tcp=%d", allowCount.Load(), denyCount.Load(), tcpCount.Load())
	return nil
}

// processAlive confirms the exact observed sing-box PID still exists immediately around a denied probe.
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
		state := "unknown"
		if len(fields) > 0 {
			state = fields[0]
		}
		return fmt.Errorf("process state is not live: %q", state)
	}
	return nil
}

// serveUDP counts each datagram and returns the supplied marker to its sender.
func serveUDP(conn net.PacketConn, marker string, count *atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		count.Add(1)
		_, _ = conn.WriteTo([]byte(marker), addr)
		logf("udp_target address=%s received=%q count=%d", conn.LocalAddr(), string(buf[:n]), count.Load())
	}
}

// serveTCPMarker counts HTTP requests and returns the fixed TCP positive-control marker.
func serveTCPMarker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tcpCount.Add(1)
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, "HSTIA-TCP-ALLOW-19181")
	logf("tcp_target address=%s count=%d", tcpAddress, tcpCount.Load())
}

// directUDPCheck sends a marker request straight to a loopback target and requires the exact response.
func directUDPCheck(target, marker string) error {
	address, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp4", nil, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	if _, err := conn.Write([]byte("DIRECT-CONTROL")); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != marker {
		return fmt.Errorf("got %q, want %q", string(buf[:n]), marker)
	}
	return nil
}

// socksTCPCheck opens a SOCKS5 CONNECT and verifies the target's HTTP marker before the shared deadline.
func socksTCPCheck(deadline time.Time) error {
	conn, err := net.DialTimeout("tcp4", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || method[0] != 5 || method[1] != 0 {
		return fmt.Errorf("SOCKS method negotiation failed: %v %v", method, err)
	}
	request := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(request[8:], 19181)
	if _, err := conn.Write(request); err != nil {
		return err
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if response[1] != 0 {
		return fmt.Errorf("SOCKS CONNECT reply code %d", response[1])
	}
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !contains(string(body), "HSTIA-TCP-ALLOW-19181") {
		return fmt.Errorf("TCP marker missing from response %q", string(body))
	}
	logf("socks_tcp result=marker_received target_count=%d", tcpCount.Load())
	return nil
}

// socksUDPCheck creates a SOCKS5 UDP association and requires the requested payload marker before timeout.
func socksUDPCheck(target, marker string, timeout time.Duration, deadline time.Time) error {
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
		return fmt.Errorf("SOCKS method negotiation failed: %v %v", method, err)
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
	probeDeadline := time.Now().Add(timeout)
	if probeDeadline.After(deadline) {
		probeDeadline = deadline
	}
	_ = udp.SetDeadline(probeDeadline)
	frame, err := socksDatagram(target, "SOCKS-UDP-MARKER-PROBE")
	if err != nil {
		return err
	}
	if _, err := udp.Write(frame); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := udp.Read(buf)
	if err != nil {
		return err
	}
	got, err := socksPayload(buf[:n])
	if err != nil {
		return err
	}
	if string(got) != marker {
		return fmt.Errorf("got UDP marker %q, want %q", string(got), marker)
	}
	count := allowCount.Load()
	if target == denyAddress {
		count = denyCount.Load()
	}
	logf("socks_udp target=%s result=marker_received target_count=%d", target, count)
	return nil
}

// socksDatagram encodes an IPv4 SOCKS5 UDP frame for a numeric loopback destination.
func socksDatagram(target, payload string) ([]byte, error) {
	address, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return nil, err
	}
	ip := address.IP.To4()
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("destination must be IPv4 loopback: %s", target)
	}
	frame := []byte{0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(frame[8:], uint16(address.Port))
	return append(frame, payload...), nil
}

// socksPayload validates and extracts the payload from an IPv4 SOCKS5 UDP response frame.
func socksPayload(frame []byte) ([]byte, error) {
	if len(frame) < 10 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 || frame[3] != 1 {
		return nil, fmt.Errorf("invalid SOCKS UDP response frame: %v", frame)
	}
	return frame[10:], nil
}

// isTimeout reports whether err is a network timeout without interpreting unrelated failures as denial.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// contains reports whether response contains the expected fixed HTTP marker.
func contains(response, marker string) bool {
	for i := 0; i+len(marker) <= len(response); i++ {
		if response[i:i+len(marker)] == marker {
			return true
		}
	}
	return false
}

// logf writes one timestamped event to standard output for the captured run transcript.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "%s "+format+"\n", append([]any{time.Now().UTC().Format(time.RFC3339Nano)}, args...)...)
}
