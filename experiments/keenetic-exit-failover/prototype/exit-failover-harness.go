// Command exit-failover-harness serves local exit markers and checks bounded SOCKS paths.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	socksAddress = "127.0.0.1:19330"
	testAddress  = "127.0.0.1:19334"
	controlAddr  = "127.0.0.1:19337"
	statsAddr    = "127.0.0.1:19338"
)

var counts = map[string]*atomic.Int64{
	"health_a": new(atomic.Int64), "health_b": new(atomic.Int64),
	"tcp_a": new(atomic.Int64), "tcp_b": new(atomic.Int64),
	"udp_a": new(atomic.Int64), "udp_b": new(atomic.Int64),
	"direct_tcp": new(atomic.Int64), "direct_udp": new(atomic.Int64),
}

// main dispatches one bounded server, TCP/UDP marker, direct-control, or statistics operation.
func main() {
	mode := flag.String("mode", "", "serve, tcp, udp, control, or stats")
	want := flag.String("expect", "", "expected marker: A, B, or any")
	duration := flag.Duration("duration", 70*time.Second, "maximum server lifetime")
	flag.Parse()
	var err error
	switch *mode {
	case "serve":
		err = serve(*duration)
	case "tcp":
		err = probeTCP(*want)
	case "udp":
		err = probeUDP(*want)
	case "control":
		err = directControl()
	case "stats":
		err = printStats()
	default:
		err = errors.New("mode must be serve, tcp, udp, control, or stats")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

// serve starts TCP and UDP marker endpoints for both synthetic exits and independent controls.
func serve(duration time.Duration) error {
	if duration <= 0 || duration > 90*time.Second {
		return errors.New("server duration must be in (0,90s]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	var servers []*http.Server
	for _, endpoint := range []struct {
		port   int
		direct bool
	}{
		{19334, false}, {19337, true},
	} {
		listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", endpoint.port))
		if err != nil {
			return fmt.Errorf("listen TCP %d: %w", endpoint.port, err)
		}
		var handler http.HandlerFunc
		if endpoint.direct {
			handler = directHTTPHandler
		} else {
			handler = exitHTTPHandler
		}
		server := &http.Server{Handler: handler}
		servers = append(servers, server)
		go func(s *http.Server, l net.Listener) { _ = s.Serve(l) }(server, listener)
		udp, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", endpoint.port))
		if err != nil {
			return fmt.Errorf("listen UDP %d: %w", endpoint.port, err)
		}
		if endpoint.direct {
			go serveUDP(ctx, udp, "direct")
		} else {
			go serveUDP(ctx, udp, "exit")
		}
	}
	statsListener, err := net.Listen("tcp4", statsAddr)
	if err != nil {
		return fmt.Errorf("listen stats endpoint: %w", err)
	}
	statsServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(snapshot())
	})}
	servers = append(servers, statsServer)
	go func() { _ = statsServer.Serve(statsListener) }()
	fmt.Printf("endpoints_ready deadline=%s ports=19334,19337,19338\n", time.Now().Add(duration).UTC().Format(time.RFC3339Nano))
	<-ctx.Done()
	for _, server := range servers {
		_ = server.Close()
	}
	return nil
}

// exitHTTPHandler identifies the exit by its loopback-only source address and counts health and TCP markers.
func exitHTTPHandler(w http.ResponseWriter, r *http.Request) {
	tag, err := exitForAddress(r.RemoteAddr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if r.URL.Path == "/health" {
		counts["health_"+tag].Add(1)
		if tag == "b" {
			time.Sleep(80 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	counts["tcp_"+tag].Add(1)
	_, _ = io.WriteString(w, "EXIT-"+strings.ToUpper(tag)+"-TCP-MARKER")
}

// directHTTPHandler returns the independent control marker and counts it separately from exit traffic.
func directHTTPHandler(w http.ResponseWriter, _ *http.Request) {
	counts["direct_tcp"].Add(1)
	_, _ = io.WriteString(w, "DIRECT-CONTROL-TCP")
}

// exitForAddress maps the synthetic VLESS server's loopback source address to its exit label.
func exitForAddress(remote string) (string, error) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return "", err
	}
	switch host {
	case "127.0.0.1":
		return "a", nil
	case "127.0.0.2":
		return "b", nil
	default:
		return "", fmt.Errorf("unexpected source address %q", host)
	}
}

// serveUDP counts local UDP markers for each synthetic exit and the independent direct control.
func serveUDP(ctx context.Context, conn net.PacketConn, tag string) {
	defer conn.Close()
	go func() { <-ctx.Done(); _ = conn.Close() }()
	buffer := make([]byte, 512)
	for {
		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		marker := "EXIT-" + strings.ToUpper(tag) + "-UDP-MARKER"
		exit := tag
		if tag == "direct" {
			counts["direct_udp"].Add(1)
			marker = "DIRECT-CONTROL-UDP"
		} else {
			exit, err = exitForAddress(addr.String())
			if err != nil {
				fmt.Printf("udp_target rejected_source=%q err=%q\n", addr.String(), err.Error())
				continue
			}
			counts["udp_"+exit].Add(1)
			marker = "EXIT-" + strings.ToUpper(exit) + "-UDP-MARKER"
		}
		fmt.Printf("udp_target exit=%s payload=%q\n", exit, string(buffer[:n]))
		_, _ = conn.WriteTo([]byte(marker), addr)
	}
}

// probeTCP requests a unique marker through the sing-box SOCKS listener.
func probeTCP(want string) error {
	conn, err := socksConnect(socksAddress, testAddress, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(conn, "GET /marker HTTP/1.0\r\nHost: loopback\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	return checkMarker("TCP", string(body), want)
}

// probeUDP sends one marker datagram through the SOCKS UDP association and validates the selected exit.
func probeUDP(want string) error {
	control, err := net.DialTimeout("tcp4", socksAddress, 8*time.Second)
	if err != nil {
		return err
	}
	defer control.Close()
	_ = control.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(control, selection); err != nil || selection[1] != 0 {
		return fmt.Errorf("SOCKS method negotiation: %v %v", selection, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil {
		return err
	}
	if reply[1] != 0 || reply[3] != 1 {
		return fmt.Errorf("SOCKS UDP ASSOCIATE reply %v", reply)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	udp, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		return err
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(8 * time.Second))
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], 19334)
	packet = append(packet, []byte("FAILOVER-UDP-PROBE")...)
	if _, err := udp.Write(packet); err != nil {
		return err
	}
	buffer := make([]byte, 256)
	n, err := udp.Read(buffer)
	if err != nil {
		return err
	}
	if n < 10 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
		return fmt.Errorf("invalid SOCKS UDP response %q", buffer[:n])
	}
	return checkMarker("UDP", string(buffer[10:n]), want)
}

// directControl proves local targets remain reachable without using either tested exit.
func directControl() error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + controlAddr + "/control")
	if err != nil {
		return err
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || !strings.Contains(string(body), "DIRECT-CONTROL-TCP") {
		return fmt.Errorf("direct TCP control: body=%q err=%v", body, err)
	}
	udp, err := net.DialTimeout("udp4", controlAddr, 3*time.Second)
	if err != nil {
		return err
	}
	defer udp.Close()
	_ = udp.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(udp, "DIRECT-CONTROL"); err != nil {
		return err
	}
	buffer := make([]byte, 128)
	n, err := udp.Read(buffer)
	if err != nil || string(buffer[:n]) != "DIRECT-CONTROL-UDP" {
		return fmt.Errorf("direct UDP control: marker=%q err=%v", buffer[:n], err)
	}
	fmt.Printf("direct_control tcp=%q udp=%q result=reachable\n", body, buffer[:n])
	return nil
}

// printStats returns marker and health counters while keeping health checks distinct from user markers.
func printStats() error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + statsAddr + "/stats")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

// snapshot reads counters as JSON-compatible values for the local statistics endpoint.
func snapshot() map[string]interface{} {
	out := make(map[string]int64, len(counts))
	for name, count := range counts {
		out[name] = count.Load()
	}
	return map[string]interface{}{"counts": out}
}

// checkMarker validates an exact expected TCP/UDP exit marker.
func checkMarker(protocol, got, want string) error {
	if want != "" && want != "any" && !strings.Contains(got, "EXIT-"+want+"-"+protocol+"-MARKER") {
		return fmt.Errorf("%s marker %q did not identify exit %s", protocol, got, want)
	}
	if !strings.Contains(got, "EXIT-") || !strings.Contains(got, "-"+protocol+"-MARKER") {
		return fmt.Errorf("invalid %s marker %q", protocol, got)
	}
	fmt.Printf("socks_%s marker=%q expected=%s result=pass\n", strings.ToLower(protocol), got, want)
	return nil
}

// socksConnect negotiates SOCKS5 and opens a TCP connection to the numeric loopback target.
func socksConnect(proxy, target string, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp4", proxy, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS method selection: %v %v", reply, err)
	}
	address, portText, err := net.SplitHostPort(target)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	ip := net.ParseIP(address).To4()
	port, err := strconv.Atoi(portText)
	if err != nil || ip == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("target must be numeric IPv4: %s", target)
	}
	if port < 1 || port > 65535 {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target port %d", port)
	}
	request := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	response := make([]byte, 10)
	if _, err := io.ReadFull(conn, response); err != nil || response[1] != 0 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS CONNECT response %v: %w", response, err)
	}
	return conn, nil
}
