//go:build linux && arm64 && !android && keenetic

package trafficcapture

import (
	"bufio"
	"context"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
)

const (
	maxNDMConntrackBytes = 4 << 20
	maxNDMConntrackLine  = 16 << 10
	ndmConntrackTimeout  = 2 * time.Second
)

// ReadNDMConntrack returns only allowlisted fields from the first exact original tuple in a bounded read-only NDM conntrack dump.
func ReadNDMConntrack(ctx context.Context, request TraceRequest) *traffic.NDMConntrackEvidence {
	observedAt := time.Now().UTC()
	result := func(status, detail string) *traffic.NDMConntrackEvidence {
		return &traffic.NDMConntrackEvidence{Status: status, ObservedAt: observedAt, Detail: detail}
	}
	ctx, cancel := context.WithTimeout(ctx, ndmConntrackTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ndmc", "-c", "show ip conntrack")
	cmd.Stderr = io.Discard
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return result("unavailable", "read-only NDM conntrack command could not be started")
	}
	if err := cmd.Start(); err != nil {
		return result("unavailable", "read-only NDM conntrack command could not be started")
	}
	limited := &io.LimitedReader{R: stdout, N: maxNDMConntrackBytes}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxNDMConntrackLine)
	for scanner.Scan() {
		if evidence, matched := parseNDMConntrackLine(scanner.Text(), request); matched {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			evidence.ObservedAt = time.Now().UTC()
			return evidence
		}
	}
	if ctx.Err() != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return result("unavailable", "read-only NDM conntrack query timed out")
	}
	if scanner.Err() != nil || limited.N == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return result("truncated", "NDM conntrack output exceeded the bounded scan before an exact tuple was found")
	}
	if err := cmd.Wait(); err != nil {
		return result("unavailable", "read-only NDM conntrack query failed")
	}
	return result("not_observed", "no exact tuple record appeared in the bounded NDM conntrack read")
}

// parseNDMConntrackLine accepts only a record whose original direction exactly matches the requested IPv4 tuple.
func parseNDMConntrackLine(line string, request TraceRequest) (*traffic.NDMConntrackEvidence, bool) {
	fields := strings.Fields(stripConntrackTerminalControls(line))
	if len(fields) < 2 || !strings.EqualFold(fields[0], request.Protocol) {
		return nil, false
	}
	values := make(map[string][]string, 12)
	flags := make([]string, 0, 4)
	for _, field := range fields[1:] {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			flag := strings.Trim(field, "[]")
			if allowedNDMConntrackFlag(flag) && len(flags) < 4 {
				flags = append(flags, flag)
			}
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if ok {
			switch key {
			case "src", "dst", "sport", "dport", "packets", "bytes", "mark", "ndmmark", "ifl", "ifw":
				values[key] = append(values[key], value)
			}
		}
	}
	if firstConntrackValue(values, "src") != request.Source || firstConntrackValue(values, "dst") != request.Destination || firstConntrackValue(values, "sport") != strconv.Itoa(request.SourcePort) || firstConntrackValue(values, "dport") != strconv.Itoa(request.DestinationPort) {
		return nil, false
	}
	evidence := &traffic.NDMConntrackEvidence{Status: "observed", ObservedAt: time.Now().UTC(), Flags: flags}
	if evidence.OriginalPackets, _ = parseConntrackCounter(values["packets"], 0); evidence.OriginalPackets == nil {
		return unavailableMatchedConntrack(), true
	}
	if evidence.OriginalBytes, _ = parseConntrackCounter(values["bytes"], 0); evidence.OriginalBytes == nil {
		return unavailableMatchedConntrack(), true
	}
	evidence.ReplyPackets, _ = parseConntrackCounter(values["packets"], 1)
	evidence.ReplyBytes, _ = parseConntrackCounter(values["bytes"], 1)
	evidence.Mark, _ = parseConntrackMark(values["mark"])
	evidence.NDMMark, _ = parseConntrackMark(values["ndmmark"])
	evidence.IFL, _ = parseConntrackIndex(values["ifl"])
	evidence.IFW, _ = parseConntrackIndex(values["ifw"])
	evidence.IFLName = allowlistedConntrackInterfaceName(evidence.IFL)
	evidence.IFWName = allowlistedConntrackInterfaceName(evidence.IFW)
	evidence.Detail = "exact original tuple found; mark is the conntrack mark and ifl/ifw are raw NDM indexes"
	return evidence, true
}

// unavailableMatchedConntrack withholds malformed or incomplete values even when the exact tuple line matched.
func unavailableMatchedConntrack() *traffic.NDMConntrackEvidence {
	return &traffic.NDMConntrackEvidence{Status: "unavailable", ObservedAt: time.Now().UTC(), Detail: "exact tuple record matched but required counters were not parseable"}
}

// firstConntrackValue returns the first occurrence of a key, which belongs to the original direction of the record.
func firstConntrackValue(values map[string][]string, key string) string {
	if len(values[key]) == 0 {
		return ""
	}
	return values[key][0]
}

// parseConntrackCounter parses one directional decimal packet or byte counter.
func parseConntrackCounter(values []string, direction int) (*uint64, bool) {
	if len(values) <= direction {
		return nil, false
	}
	value, err := strconv.ParseUint(values[direction], 10, 64)
	if err != nil {
		return nil, false
	}
	return &value, true
}

// parseConntrackMark parses one optional hexadecimal packet/connection mark.
func parseConntrackMark(values []string) (*uint64, bool) {
	if len(values) == 0 {
		return nil, false
	}
	value, err := strconv.ParseUint(values[0], 0, 32)
	if err != nil {
		return nil, false
	}
	return &value, true
}

// parseConntrackIndex parses one optional decimal NDM interface index.
func parseConntrackIndex(values []string) (*uint32, bool) {
	if len(values) == 0 {
		return nil, false
	}
	value, err := strconv.ParseUint(values[0], 10, 32)
	if err != nil {
		return nil, false
	}
	index := uint32(value)
	return &index, true
}

// allowedNDMConntrackFlag retains only known conntrack states relevant to this bounded trace.
func allowedNDMConntrackFlag(flag string) bool {
	switch flag {
	case "ASSURED", "UNREPLIED", "SEEN_REPLY", "FASTNAT":
		return true
	default:
		return false
	}
}

// allowlistedConntrackInterfaceName maps only the two trace interfaces and omits every other interface name.
func allowlistedConntrackInterfaceName(index *uint32) string {
	if index == nil {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(*index))
	if err != nil || (iface.Name != "br0" && iface.Name != "opkgtun0") {
		return ""
	}
	return iface.Name
}

// stripConntrackTerminalControls removes ANSI CSI sequences before tokenizing NDM's human-readable output.
func stripConntrackTerminalControls(line string) string {
	var result strings.Builder
	for index := 0; index < len(line); index++ {
		if line[index] != 0x1b || index+1 >= len(line) || line[index+1] != '[' {
			result.WriteByte(line[index])
			continue
		}
		index += 2
		for index < len(line) && (line[index] < '@' || line[index] > '~') {
			index++
		}
	}
	return result.String()
}
