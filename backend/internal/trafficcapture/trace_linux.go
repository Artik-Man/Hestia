//go:build linux && arm64 && !android && keenetic

package trafficcapture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/unix"
)

// TraceRequest bounds a diagnostic session to one IPv4 TCP/UDP flow and a short duration.
type TraceRequest struct {
	Protocol        string `json:"protocol"`
	Source          string `json:"source"`
	SourcePort      int    `json:"sourcePort"`
	Destination     string `json:"destination"`
	DestinationPort int    `json:"destinationPort"`
	DurationSeconds int    `json:"durationSeconds"`
}

// TraceResult contains only tuple-scoped stage counts and never packet bytes.
type TraceResult struct {
	StartedAt               time.Time                     `json:"startedAt"`
	ConfigurationObservedAt *time.Time                    `json:"configurationObservedAt,omitempty"`
	DurationMs              int                           `json:"durationMs"`
	PolicyKey               string                        `json:"policyKey"`
	ConfiguredMark          uint32                        `json:"configuredMark,omitempty"`
	NDMTable                uint32                        `json:"ndmTable,omitempty"`
	HestiaTable             uint32                        `json:"hestiaTable,omitempty"`
	Protocol                string                        `json:"protocol"`
	Source                  string                        `json:"source"`
	SourcePort              int                           `json:"sourcePort"`
	Destination             string                        `json:"destination"`
	DestinationPort         int                           `json:"destinationPort"`
	NDMConntrack            *traffic.NDMConntrackEvidence `json:"ndmConntrack,omitempty"`
	Stages                  []TraceStageResult            `json:"stages"`
}

const (
	maxTraceLogMessages = 512
	maxTraceLogBytes    = 1 << 20
)

// traceCaptureResult transports one interface's count and setup/read error to the session aggregator.
type traceCaptureResult struct {
	name    string
	forward int
	reverse int
	err     error
}

// ValidateTraceRequest rejects non-IPv4 tuples and durations outside the fixed operator window.
func ValidateTraceRequest(r TraceRequest) error {
	src, err := netip.ParseAddr(r.Source)
	if err != nil || !src.Is4() {
		return errors.New("source must be an IPv4 address")
	}
	dst, err := netip.ParseAddr(r.Destination)
	if err != nil || !dst.Is4() {
		return errors.New("destination must be an IPv4 address")
	}
	if r.Protocol != "TCP" && r.Protocol != "UDP" {
		return errors.New("protocol must be TCP or UDP")
	}
	if r.SourcePort < 1 || r.SourcePort > 65535 || r.DestinationPort < 1 || r.DestinationPort > 65535 {
		return errors.New("ports must be between 1 and 65535")
	}
	if r.DurationSeconds < 1 || r.DurationSeconds > 15 {
		return errors.New("durationSeconds must be between 1 and 15")
	}
	return nil
}

// DecodeTraceRequest accepts exactly one bounded JSON request from standard input.
func DecodeTraceRequest(input []byte) (TraceRequest, error) {
	var r TraceRequest
	if len(input) > 2048 {
		return r, errors.New("trace request exceeds 2048 bytes")
	}
	d := json.NewDecoder(strings.NewReader(string(input)))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return r, errors.New("trace request must contain one JSON object")
	}
	return r, ValidateTraceRequest(r)
}

// CaptureTrace observes matching IPv4 packet headers on the two validated Hestia path interfaces.
func CaptureTrace(ctx context.Context, r TraceRequest) TraceResult {
	started := time.Now().UTC()
	result := TraceResult{StartedAt: started, Protocol: r.Protocol, Source: r.Source, SourcePort: r.SourcePort, Destination: r.Destination, DestinationPort: r.DestinationPort, Stages: make([]TraceStageResult, 0, traffic.MaxTraceStages)}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.DurationSeconds)*time.Second)
	defer cancel()
	singBox := make(chan []TraceStageResult, 1)
	go func() { singBox <- traceSingBox(ctx, r) }()
	out := make(chan traceCaptureResult, 4)
	for _, name := range []string{"br0", "opkgtun0"} {
		go captureInterface(ctx, name, r, false, out)
		go captureInterface(ctx, name, r, true, out)
	}
	counts := map[string][2]int{}
	for i := 0; i < 4; i++ {
		c := <-out
		counts[c.name] = [2]int{counts[c.name][0] + c.forward, counts[c.name][1] + c.reverse}
		if c.err != nil {
			counts[c.name] = [2]int{-1, -1}
		}
	}
	for _, name := range []string{"br0", "opkgtun0"} {
		pair := counts[name]
		status, detail := "not_observed", "no matching IPv4 header observed (IPv4 options and fragmented packets are excluded)"
		if pair[0] < 0 {
			status, detail = "unavailable", "header capture unavailable"
		} else if pair[0]+pair[1] > 0 {
			status, detail = "observed", "matching tuple headers observed; reverse count is the response direction"
		}
		result.Stages = append(result.Stages, TraceStageResult{Name: name, Status: status, Count: max(0, pair[0]), ReverseCount: max(0, pair[1]), Detail: detail})
	}
	result.DurationMs = boundedTraceDuration(time.Since(started), r.DurationSeconds)
	result.Stages = append(result.Stages, <-singBox...)
	result.Stages = append(result.Stages, TraceStageResult{Name: "policy_mark", Status: "unavailable", Detail: "direct skb mark at the RPDB hook is not observed; conntrack mark is reported separately"}, TraceStageResult{Name: "wan", Status: "unavailable", Detail: "WAN capture is not enabled"})
	return result
}

// traceSingBox subscribes for the same bounded interval and correlates only contexts that expose the exact IPv4 5-tuple.
func traceSingBox(ctx context.Context, r TraceRequest) []TraceStageResult {
	stages := map[string]bool{"sing_box_inbound": false, "sing_box_rule": false, "sing_box_group": false, "sing_box_outbound": false, "sing_box_block": false}
	endpoint, err := websocket.NewConfig(gatewayLog, "http://127.0.0.1")
	if err != nil {
		return unavailableSingBoxStages()
	}
	dialCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	conn, err := endpoint.DialContext(dialCtx)
	stop()
	if err != nil {
		return unavailableSingBoxStages()
	}
	defer conn.Close()
	conn.MaxPayloadBytes = 64 << 10
	stopRead := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stopRead()
	contexts := map[string]bool{}
	messageCount, messageBytes := 0, 0
	truncated, unavailable := false, false
	for ctx.Err() == nil {
		var entry struct {
			Payload string `json:"payload"`
		}
		if err := websocket.JSON.Receive(conn, &entry); err != nil {
			unavailable = ctx.Err() == nil
			break
		}
		messageCount++
		messageBytes += len(entry.Payload)
		if messageCount > maxTraceLogMessages || messageBytes > maxTraceLogBytes {
			truncated = true
			break
		}
		fields := contextLine.FindStringSubmatch(entry.Payload)
		if fields == nil {
			continue
		}
		id, logger, detail := fields[1], fields[2], fields[3]
		if clientInbound.MatchString(logger) {
			proto, rest, ok := strings.Cut(detail, " from ")
			if !ok {
				continue
			}
			source, dest, ok := strings.Cut(rest, " to ")
			if !ok {
				continue
			}
			wantProto := "inbound connection"
			if r.Protocol == "UDP" {
				wantProto = "inbound packet connection"
			}
			if proto != wantProto {
				continue
			}
			if endpointMatches(source, r.Source, r.SourcePort) && endpointMatches(dest, r.Destination, r.DestinationPort) && (contexts[id] || len(contexts) < 128) {
				contexts[id] = true
				stages["sing_box_inbound"] = true
			} else if endpointMatches(source, r.Source, r.SourcePort) && endpointMatches(dest, r.Destination, r.DestinationPort) {
				truncated = true
				break
			}
			continue
		}
		if !contexts[id] {
			continue
		}
		if logger == "router" {
			if strings.HasPrefix(detail, "match[") {
				stages["sing_box_rule"] = true
				if strings.Contains(detail, "route(") {
					stages["sing_box_group"] = true
				}
			}
			continue
		}
		if clientOutbound.MatchString(logger) {
			if strings.HasPrefix(detail, "blocked ") {
				stages["sing_box_block"] = true
			} else if strings.HasPrefix(detail, "outbound ") {
				stages["sing_box_outbound"] = true
			}
		}
	}
	result := make([]TraceStageResult, 0, len(stages))
	for _, name := range []string{"sing_box_inbound", "sing_box_rule", "sing_box_group", "sing_box_outbound", "sing_box_block"} {
		seen := stages[name]
		status, detail := "not_observed", "connected log stream had no exact-tuple evidence for this stage"
		if seen {
			status, detail = "observed", "exact-tuple context observed in sing-box log stream"
		} else if truncated {
			status, detail = "truncated", "aggregate log frame or byte limit reached before this stage was observed"
		} else if unavailable {
			status, detail = "unavailable", "gateway log stream ended before the session window completed"
		}
		result = append(result, TraceStageResult{Name: name, Status: status, Detail: detail})
	}
	result = append(result, TraceStageResult{Name: "sing_box_response", Status: "unavailable", Detail: "response is measured by reverse tuple counts on packet interfaces"}, TraceStageResult{Name: "sing_box_close", Status: "unavailable", Detail: "current gateway log parser does not expose close events"})
	return result
}

// endpointMatches compares a numeric log endpoint with one exact IPv4 address and port.
func endpointMatches(value, address string, port int) bool {
	host, raw, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || !parsed.Is4() {
		return false
	}
	actual, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	return parsed.String() == address && actual == port
}

// unavailableSingBoxStages marks every unsupported log stage unavailable when subscription setup fails.
func unavailableSingBoxStages() []TraceStageResult {
	names := []string{"sing_box_inbound", "sing_box_rule", "sing_box_group", "sing_box_outbound", "sing_box_block", "sing_box_response", "sing_box_close"}
	out := make([]TraceStageResult, 0, len(names))
	for _, name := range names {
		out = append(out, TraceStageResult{Name: name, Status: "unavailable", Detail: "gateway log subscription unavailable"})
	}
	return out
}

// captureInterface installs a kernel BPF tuple filter and counts matching header-only frames until cancellation.
func captureInterface(ctx context.Context, name string, r TraceRequest, reverse bool, out chan<- traceCaptureResult) {
	if reverse {
		r.Source, r.Destination = r.Destination, r.Source
		r.SourcePort, r.DestinationPort = r.DestinationPort, r.SourcePort
	}
	count, err := capture(ctx, name, r)
	result := traceCaptureResult{name: name, err: err}
	if reverse {
		result.reverse = count
	} else {
		result.forward = count
	}
	out <- result
}

// capture opens a raw packet socket, attaches a tuple-specific BPF program, and discards every read frame.
func capture(ctx context.Context, name string, r TraceRequest) (int, error) {
	idx, err := netInterfaceIndex(name)
	if err != nil {
		return 0, err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	prog := tupleFilter(name, r)
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return 0, err
	}
	addr := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: idx}
	if err = unix.Bind(fd, addr); err != nil {
		return 0, err
	}
	buf := make([]byte, 128)
	count := 0
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		n, _, e := unix.Recvfrom(fd, buf, unix.MSG_DONTWAIT)
		if e == nil && n > 0 {
			if matchesTuple(buf[:n], name, r) {
				count++
			}
			continue
		}
		if e != nil && e != unix.EAGAIN && e != unix.EWOULDBLOCK && e != unix.EINTR {
			return count, e
		}
		select {
		case <-ctx.Done():
			return count, nil
		case <-tick.C:
		}
	}
}

// netInterfaceIndex resolves only the fixed kernel interface name selected by CaptureTrace.
func netInterfaceIndex(name string) (int, error) { return netInterfaceByName(name) }

// netInterfaceByName resolves a kernel interface index through the operating system interface table.
func netInterfaceByName(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// tupleFilter creates a classic BPF program matching one IPv4 TCP/UDP 5-tuple at Ethernet or raw-IP offsets.
func tupleFilter(name string, r TraceRequest) unix.SockFprog {
	base := 0
	if name == "br0" {
		base = 14
	}
	code := make([]unix.SockFilter, 0, 16)
	add := func(op uint16, k uint32) { code = append(code, unix.SockFilter{Code: op, K: k}) }
	check := func(load uint16, off uint32, k uint32) {
		add(load, off)
		code = append(code, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: k})
		add(unix.BPF_RET|unix.BPF_K, 0)
	}
	if base != 0 {
		check(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, 12, uint32(unix.ETH_P_IP))
	}
	check(unix.BPF_LD|unix.BPF_B|unix.BPF_ABS, uint32(base), 0x45)
	add(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, uint32(base+6))
	add(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, 0x3fff)
	code = append(code, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: 0})
	add(unix.BPF_RET|unix.BPF_K, 0)
	proto := uint32(6)
	if r.Protocol == "UDP" {
		proto = 17
	}
	check(unix.BPF_LD|unix.BPF_B|unix.BPF_ABS, uint32(base+9), proto)
	src := netip.MustParseAddr(r.Source).As4()
	dst := netip.MustParseAddr(r.Destination).As4()
	check(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, uint32(base+12), uint32(src[0])<<24|uint32(src[1])<<16|uint32(src[2])<<8|uint32(src[3]))
	check(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, uint32(base+16), uint32(dst[0])<<24|uint32(dst[1])<<16|uint32(dst[2])<<8|uint32(dst[3]))
	check(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, uint32(base+20), uint32(r.SourcePort))
	check(unix.BPF_LD|unix.BPF_H|unix.BPF_ABS, uint32(base+22), uint32(r.DestinationPort))
	snaplen := uint32(40)
	if r.Protocol == "UDP" {
		snaplen = 28
	}
	if base != 0 {
		snaplen += 14
	}
	add(unix.BPF_RET|unix.BPF_K, snaplen)
	return unix.SockFprog{Len: uint16(len(code)), Filter: &code[0]}
}

// matchesTuple verifies a received frame against the exact tuple before increasing the summary count.
func matchesTuple(b []byte, name string, r TraceRequest) bool {
	off := 0
	if name == "br0" {
		off = 14
	}
	if len(b) < off+24 {
		return false
	}
	proto := byte(6)
	if r.Protocol == "UDP" {
		proto = 17
	}
	return b[off+9] == proto && netip.AddrFrom4([4]byte(b[off+12:off+16])).String() == r.Source && netip.AddrFrom4([4]byte(b[off+16:off+20])).String() == r.Destination && int(b[off+20])<<8|int(b[off+21]) == r.SourcePort && int(b[off+22])<<8|int(b[off+23]) == r.DestinationPort
}

// htons converts a host-order protocol number into the network order expected by AF_PACKET.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
