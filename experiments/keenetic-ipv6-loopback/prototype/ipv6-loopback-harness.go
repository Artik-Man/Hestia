// Command ipv6-loopback-harness probes sing-box SOCKS TCP and UDP using only ::1.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	socksAddress   = "[::1]:19430"
	allowTCP       = "[::1]:19431"
	allowUDP       = "[::1]:19432"
	denyTCP        = "[::1]:19433"
	denyUDP        = "[::1]:19434"
	allowTCPMarker = "HSTIA-IPV6-TCP-ALLOW-19431"
	allowUDPMarker = "HSTIA-IPV6-UDP-ALLOW-19432"
	denyTCPMarker  = "HSTIA-IPV6-TCP-DENY-WITNESS-19433"
	denyUDPMarker  = "HSTIA-IPV6-UDP-DENY-WITNESS-19434"
)

var allowTCPCount atomic.Int64
var allowUDPCount atomic.Int64
var denyTCPCount atomic.Int64
var denyUDPCount atomic.Int64

// main starts IPv6 loopback marker endpoints, probes allowed and blocked SOCKS traffic, and exits nonzero on a mismatch.
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

// run binds the four reserved ::1 endpoints, runs bounded SOCKS checks, and closes all listeners.
func run(duration time.Duration, daemonPID int) error {
	allowPacket, err := net.ListenPacket("udp6", allowUDP)
	if err != nil {
		return fmt.Errorf("bind allowed UDP endpoint: %w", err)
	}
	defer allowPacket.Close()
	denyPacket, err := net.ListenPacket("udp6", denyUDP)
	if err != nil {
		return fmt.Errorf("bind denied UDP witness: %w", err)
	}
	defer denyPacket.Close()
	allowListener, err := net.Listen("tcp6", allowTCP)
	if err != nil {
		return fmt.Errorf("bind allowed TCP endpoint: %w", err)
	}
	defer allowListener.Close()
	denyListener, err := net.Listen("tcp6", denyTCP)
	if err != nil {
		return fmt.Errorf("bind denied TCP witness: %w", err)
	}
	defer denyListener.Close()
	go serveUDP(allowPacket, allowUDPMarker, &allowUDPCount)
	go serveUDP(denyPacket, denyUDPMarker, &denyUDPCount)
	go serveTCP(allowListener, allowTCPMarker, &allowTCPCount)
	go serveTCP(denyListener, denyTCPMarker, &denyTCPCount)
	deadline := time.Now().Add(duration)
	logf("endpoints_ready family=ipv6 address=::1 socks=%s allow_tcp=%s allow_udp=%s deny_tcp=%s deny_udp=%s deadline=%s", socksAddress, allowTCP, allowUDP, denyTCP, denyUDP, deadline.UTC().Format(time.RFC3339Nano))

	if err := directUDPCheck(denyUDP, denyUDPMarker); err != nil {
		return fmt.Errorf("direct UDP control: %w", err)
	}
	if err := directTCPCheck(denyTCP, denyTCPMarker, deadline); err != nil {
		return fmt.Errorf("direct TCP control: %w", err)
	}
	logf("direct_controls tcp_count=%d udp_count=%d result=markers_received", denyTCPCount.Load(), denyUDPCount.Load())
	if err := socksTCPCheck(allowTCP, allowTCPMarker, deadline); err != nil {
		return fmt.Errorf("SOCKS TCP allow check: %w", err)
	}
	if err := socksUDPCheck(allowUDP, allowUDPMarker, deadline); err != nil {
		return fmt.Errorf("SOCKS UDP allow check: %w", err)
	}
	if err := processAlive(daemonPID); err != nil {
		return fmt.Errorf("sing-box was not alive before blocked probes: %w", err)
	}
	beforeTCP, beforeUDP := denyTCPCount.Load(), denyUDPCount.Load()
	if err := socksTCPBlockedCheck(denyTCP, denyTCPMarker, deadline); err != nil {
		return fmt.Errorf("SOCKS TCP block check: %w", err)
	}
	if err := socksUDPBlockedCheck(denyUDP, denyUDPMarker, deadline); err != nil {
		return fmt.Errorf("SOCKS UDP block check: %w", err)
	}
	if err := processAlive(daemonPID); err != nil {
		return fmt.Errorf("sing-box was not alive after blocked probes: %w", err)
	}
	if denyTCPCount.Load() != beforeTCP || denyUDPCount.Load() != beforeUDP {
		return fmt.Errorf("denied endpoint counter changed: tcp %d->%d udp %d->%d", beforeTCP, denyTCPCount.Load(), beforeUDP, denyUDPCount.Load())
	}
	logf("blocked_probes result=no_markers tcp_count_before=%d tcp_count_after=%d udp_count_before=%d udp_count_after=%d", beforeTCP, denyTCPCount.Load(), beforeUDP, denyUDPCount.Load())
	logf("final_counts allow_tcp=%d allow_udp=%d deny_tcp=%d deny_udp=%d", allowTCPCount.Load(), allowUDPCount.Load(), denyTCPCount.Load(), denyUDPCount.Load())
	return nil
}

// processAlive confirms the exact observed sing-box PID exists and is not a zombie.
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
		return fmt.Errorf("process state is not live: %q", fields)
	}
	return nil
}

// serveUDP counts datagrams on one IPv6 loopback socket and returns its fixed marker.
func serveUDP(conn net.PacketConn, marker string, count *atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		count.Add(1)
		_, _ = conn.WriteTo([]byte(marker), addr)
		logf("udp_endpoint address=%s received=%q count=%d", conn.LocalAddr(), string(buf[:n]), count.Load())
	}
}

// serveTCP accepts local marker requests, counts them, and returns one fixed response.
func serveTCP(listener net.Listener, marker string, count *atomic.Int64) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			count.Add(1)
			_, _ = io.WriteString(conn, marker)
			logf("tcp_endpoint address=%s count=%d", listener.Addr(), count.Load())
		}()
	}
}

// directTCPCheck verifies an IPv6 loopback TCP endpoint can return its marker outside SOCKS.
func directTCPCheck(target, marker string, deadline time.Time) error {
	conn, err := net.DialTimeout("tcp6", target, time.Until(deadline))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := io.WriteString(conn, "DIRECT-CONTROL"); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != marker {
		return fmt.Errorf("got %q, want %q", buf[:n], marker)
	}
	return nil
}

// directUDPCheck verifies an IPv6 loopback UDP endpoint can return its marker outside SOCKS.
func directUDPCheck(target, marker string) error {
	address, err := net.ResolveUDPAddr("udp6", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp6", nil, address)
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
		return fmt.Errorf("got %q, want %q", buf[:n], marker)
	}
	return nil
}

// socksTCPCheck performs SOCKS5 CONNECT with an IPv6 ATYP target and requires its marker.
func socksTCPCheck(target, marker string, deadline time.Time) error {
	conn, err := net.DialTimeout("tcp6", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if err := socksNegotiate(conn); err != nil {
		return err
	}
	request, err := socksTCPRequest(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return err
	}
	response, err := readSOCKSAddress(conn)
	if err != nil || response[1] != 0 {
		return fmt.Errorf("SOCKS CONNECT reply=%v error=%v", response, err)
	}
	if _, err := io.WriteString(conn, "SOCKS-TCP-PROBE"); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if string(buf[:n]) != marker {
		return fmt.Errorf("got %q, want %q", buf[:n], marker)
	}
	logf("socks_tcp target=%s result=marker_received", target)
	return nil
}

// socksUDPCheck creates a SOCKS5 UDP relay and requires the IPv6 target's positive marker.
func socksUDPCheck(target, marker string, deadline time.Time) error {
	control, err := net.DialTimeout("tcp6", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(deadline)
	if err := socksNegotiate(control); err != nil {
		return err
	}
	if _, err := control.Write([]byte{5, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	response, err := readSOCKSAddress(control)
	if err != nil || response[1] != 0 {
		return fmt.Errorf("SOCKS UDP ASSOCIATE reply=%v error=%v", response, err)
	}
	if response[3] != 4 {
		return fmt.Errorf("expected IPv6 relay address, reply=%v", response)
	}
	relay := &net.UDPAddr{IP: net.IP(response[4:20]), Port: int(binary.BigEndian.Uint16(response[20:22]))}
	udp, err := net.DialUDP("udp6", nil, relay)
	if err != nil {
		return err
	}
	defer udp.Close()
	_ = udp.SetDeadline(deadline)
	frame, err := socksUDPFrame(target, "SOCKS-UDP-PROBE")
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
	payload, err := socksUDPPayload(buf[:n])
	if err != nil {
		return err
	}
	if string(payload) != marker {
		return fmt.Errorf("got UDP marker %q, want %q", payload, marker)
	}
	logf("socks_udp target=%s result=marker_received", target)
	return nil
}

// socksTCPBlockedCheck requires no marker from the denied TCP witness and tolerates normal SOCKS block errors.
func socksTCPBlockedCheck(target, marker string, deadline time.Time) error {
	conn, err := net.DialTimeout("tcp6", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if err := socksNegotiate(conn); err != nil {
		return err
	}
	request, err := socksTCPRequest(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return err
	}
	response, err := readSOCKSAddress(conn)
	if err == nil && response[1] == 0 {
		_, _ = io.WriteString(conn, "SOCKS-TCP-DENY-PROBE")
		buf := make([]byte, 256)
		n, readErr := conn.Read(buf)
		if readErr == nil && strings.Contains(string(buf[:n]), marker) {
			return fmt.Errorf("denied TCP witness returned marker %q", marker)
		}
	} else if err != nil && !isExpectedConnectionClose(err) {
		return err
	}
	logf("socks_tcp target=%s result=no_witness_marker reply=%v error=%v", target, response, err)
	return nil
}

// socksUDPBlockedCheck requires the denied UDP witness to remain silent for a bounded receive interval.
func socksUDPBlockedCheck(target, marker string, deadline time.Time) error {
	control, err := net.DialTimeout("tcp6", socksAddress, time.Until(deadline))
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(deadline)
	if err := socksNegotiate(control); err != nil {
		return err
	}
	if _, err := control.Write([]byte{5, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	response, err := readSOCKSAddress(control)
	if err != nil || response[1] != 0 || response[3] != 4 {
		return fmt.Errorf("SOCKS UDP ASSOCIATE reply=%v error=%v", response, err)
	}
	relay := &net.UDPAddr{IP: net.IP(response[4:20]), Port: int(binary.BigEndian.Uint16(response[20:22]))}
	udp, err := net.DialUDP("udp6", nil, relay)
	if err != nil {
		return err
	}
	defer udp.Close()
	probeDeadline := time.Now().Add(1200 * time.Millisecond)
	if probeDeadline.After(deadline) {
		probeDeadline = deadline
	}
	_ = udp.SetDeadline(probeDeadline)
	frame, err := socksUDPFrame(target, "SOCKS-UDP-DENY-PROBE")
	if err != nil {
		return err
	}
	if _, err := udp.Write(frame); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := udp.Read(buf)
	if err == nil {
		payload, parseErr := socksUDPPayload(buf[:n])
		if parseErr == nil && string(payload) == marker {
			return fmt.Errorf("denied UDP witness returned marker %q", marker)
		}
		return fmt.Errorf("unexpected SOCKS UDP response payload=%q parse_error=%v", payload, parseErr)
	}
	if !isTimeout(err) {
		return err
	}
	logf("socks_udp target=%s result=timeout error=%q", target, err.Error())
	return nil
}

// socksNegotiate selects the no-authentication method and validates the SOCKS5 greeting response.
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

// socksTCPRequest encodes a numeric IPv6 destination for a SOCKS5 CONNECT request.
func socksTCPRequest(target string) ([]byte, error) {
	address, err := net.ResolveTCPAddr("tcp6", target)
	if err != nil || address.IP.To16() == nil || !address.IP.IsLoopback() {
		return nil, fmt.Errorf("destination must be numeric IPv6 loopback: %s", target)
	}
	request := []byte{5, 1, 0, 4}
	request = append(request, address.IP.To16()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(address.Port))
	return append(append(request, port...), nil...), nil
}

// socksUDPFrame encodes a SOCKS5 UDP datagram for a numeric IPv6 loopback destination.
func socksUDPFrame(target, payload string) ([]byte, error) {
	address, err := net.ResolveUDPAddr("udp6", target)
	if err != nil || address.IP.To16() == nil || !address.IP.IsLoopback() {
		return nil, fmt.Errorf("destination must be numeric IPv6 loopback: %s", target)
	}
	frame := []byte{0, 0, 0, 4}
	frame = append(frame, address.IP.To16()...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(address.Port))
	frame = append(frame, port...)
	return append(frame, payload...), nil
}

// readSOCKSAddress reads a SOCKS5 reply through its variable-length bound address.
func readSOCKSAddress(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := 0
	switch header[3] {
	case 1:
		length = 4
	case 3:
		nameLength := []byte{0}
		if _, err := io.ReadFull(conn, nameLength); err != nil {
			return nil, err
		}
		return readSOCKSTail(conn, append(header, nameLength...), int(nameLength[0])+2)
	case 4:
		length = 16
	default:
		return nil, fmt.Errorf("invalid SOCKS address type %d", header[3])
	}
	return readSOCKSTail(conn, header, length+2)
}

// readSOCKSTail appends the requested address and port bytes to a SOCKS5 reply header.
func readSOCKSTail(conn net.Conn, header []byte, length int) ([]byte, error) {
	tail := make([]byte, length)
	if _, err := io.ReadFull(conn, tail); err != nil {
		return nil, err
	}
	return append(header, tail...), nil
}

// socksUDPPayload validates an IPv6 SOCKS5 UDP frame and extracts its payload.
func socksUDPPayload(frame []byte) ([]byte, error) {
	if len(frame) < 22 || frame[0] != 0 || frame[1] != 0 || frame[2] != 0 || frame[3] != 4 {
		return nil, fmt.Errorf("invalid IPv6 SOCKS UDP response frame: %v", frame)
	}
	return frame[22:], nil
}

// isExpectedConnectionClose identifies ordinary SOCKS block replies that close or reset a TCP connection.
func isExpectedConnectionClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// isTimeout reports whether an error is a network timeout.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// logf writes one UTC timestamped event for an auditable bounded run transcript.
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "%s "+format+"\n", append([]any{time.Now().UTC().Format(time.RFC3339Nano)}, args...)...)
}
