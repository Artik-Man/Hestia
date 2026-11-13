// Package trafficcapture reads the gateway's local sing-box flow log without changing routing.
package trafficcapture

import (
	"container/list"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/traffic"
)

const maxPending = 4096
const attributionWindow = 5 * time.Second

var (
	fastForward    = regexp.MustCompile(`^pre-match: forward (tcp|udp) connection from [^ ]+ to ([^ ]+) via (outbound/[a-z0-9-]+\[` + awg.ConnectionIDPattern + `\])$`)
	contextLine    = regexp.MustCompile(`^\[([0-9]{1,10}) [^\] ]{1,24}\] ([^: ]+): ([^\r\n]+)$`)
	clientInbound  = regexp.MustCompile(`^inbound/(?:tun|socks)\[([a-zA-Z0-9-]+)\]$`)
	clientOutbound = regexp.MustCompile(`^(?:outbound/[a-z0-9-]+|endpoint/wireguard)\[(` + awg.ConnectionIDPattern + `)\]$`)
	groupRoute     = regexp.MustCompile(`^route\((` + awg.ConnectionIDPattern + `)\)$`)
	hostName       = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*\.?$`)
)

// pendingFlow holds one ingress observation until a decision arrives or the attribution window ends.
type pendingFlow struct {
	contextID       string
	resolvedHost    string
	resolvedAddress netip.Addr
	event           traffic.TrafficEvent
}

// parser matches only bounded, same-context observations within one sing-box log subscription.
type parser struct {
	byID  map[string]*list.Element
	order list.List
	emit  func(traffic.TrafficEvent)
}

// newParser starts an empty subscription and emits each completed ingress observation once.
func newParser(emit func(traffic.TrafficEvent)) *parser {
	return &parser{byID: make(map[string]*list.Element), emit: emit}
}

// accept correlates documented gateway log formats; DNS-only, quality and transport logs cannot start records.
func (p *parser) accept(now time.Time, message string) {
	fields := contextLine.FindStringSubmatch(message)
	if fields == nil {
		return
	}
	id, logger, detail := fields[1], fields[2], fields[3]
	if clientInbound.MatchString(logger) {
		protocol, endpoint, ok := strings.Cut(detail, " to ")
		if !ok || (protocol != "inbound connection" && protocol != "inbound packet connection") {
			return
		}
		host, port, ok := destination(endpoint)
		if !ok {
			return
		}
		e := traffic.TrafficEvent{Time: now, Protocol: "TCP", Port: port, Kind: traffic.Unconfirmed}
		if protocol == "inbound packet connection" {
			e.Protocol = "UDP"
		}
		setDestination(&e, host)
		if old := p.byID[id]; old != nil {
			p.finish(old, true)
		}
		if p.order.Len() >= maxPending {
			p.finish(p.order.Front(), true)
		}
		p.byID[id] = p.order.PushBack(&pendingFlow{contextID: id, event: e})
		return
	}
	elm := p.byID[id]
	if elm == nil {
		if logger == "router" && strings.HasPrefix(detail, "pre-match: forward ") {
			p.forward(now, detail)
		}
		return
	}
	flow := elm.Value.(*pendingFlow)
	e := &flow.event
	if logger == "router" {
		p.router(elm, detail)
		return
	}
	out := clientOutbound.FindStringSubmatch(logger)
	if out == nil {
		return
	}
	action, endpoint, _ := strings.Cut(detail, " to ")
	blocked := strings.HasPrefix(logger, "outbound/block[") && (action == "blocked connection" || action == "blocked packet connection")
	if !blocked && action != "outbound connection" && action != "outbound packet connection" {
		return
	}
	if host, port, ok := destination(endpoint); ok && port == e.Port {
		setDestination(e, host)
	}
	if e.Address == "" && flow.resolvedHost == e.Domain && flow.resolvedAddress.IsValid() {
		e.Address = flow.resolvedAddress.String()
	}
	// A direct route can name an individual exit rather than a selector.
	if e.Group == out[1] {
		e.Group = ""
	}
	if blocked {
		e.Kind = traffic.Blocked
		e.BlockReason = "Заблокировано выходом " + out[1]
	} else if out[1] == "deny" {
		e.Kind = traffic.Blocked
		e.BlockReason = "Выбран запрещающий выход deny"
	} else {
		e.Connection = out[1]
	}
	p.finish(elm, true)
}

// router saves same-flow route, sniffed QUIC and block/FakeIP evidence, releasing hijacked DNS without a flow.
func (p *parser) router(elm *list.Element, detail string) {
	e := &elm.Value.(*pendingFlow).event
	if name, ok := strings.CutPrefix(detail, "found fakeip domain: "); ok && validDomain(name) {
		e.FakeIP, e.Address, e.Domain = e.Address, "", name
		return
	}
	if rest, ok := strings.CutPrefix(detail, "resolved ["); ok && strings.HasSuffix(rest, "]") {
		flow := elm.Value.(*pendingFlow)
		flow.resolvedHost = e.Domain
		flow.resolvedAddress, _ = netip.ParseAddr(strings.TrimSuffix(rest, "]"))
		return
	}
	if strings.HasPrefix(detail, "sniffed ") {
		if protocol, ok := strings.CutPrefix(detail, "sniffed packet protocol: "); ok && e.Protocol == "UDP" {
			protocol, _, _ = strings.Cut(protocol, ", ")
			if protocol == "quic" {
				e.Protocol = "QUIC"
			}
		}
		_, name, ok := strings.Cut(detail, ", domain: ")
		name, _, _ = strings.Cut(name, ", ")
		if ok && validDomain(name) {
			e.Domain = name
		}
		return
	}
	if !strings.HasPrefix(detail, "match[") {
		return
	}
	rule, action, ok := strings.Cut(detail, " => ")
	if !ok {
		return
	}
	if action == "hijack-dns" {
		p.finish(elm, false)
		return
	}
	if action == "reject" || strings.HasPrefix(action, "reject(") {
		e.Kind = traffic.Blocked
		e.BlockReason = "Правило sing-box отклонило поток"
	} else if group := groupRoute.FindStringSubmatch(action); group != nil {
		e.Group = group[1]
	} else {
		return
	}
	if len(rule) <= 512 {
		e.Reason = rule
	}
	if e.Kind == traffic.Blocked {
		p.finish(elm, true)
	}
}

// forward records a TUN fast-path tracker attachment. This log omits both ports and OS interface.
func (p *parser) forward(now time.Time, detail string) {
	parts := fastForward.FindStringSubmatch(detail)
	if parts == nil {
		return
	}
	host := parts[2]
	if _, err := netip.ParseAddr(host); err != nil && !validDomain(host) {
		return
	}
	tag := clientOutbound.FindStringSubmatch(parts[3])
	if tag == nil {
		return
	}
	e := traffic.TrafficEvent{Time: now, Protocol: strings.ToUpper(parts[1]), Kind: traffic.Unconfirmed, Connection: tag[1]}
	setDestination(&e, host)
	p.emit(e)
}

// destination splits a numeric port and a bounded hostname or numeric destination without performing DNS.
func destination(endpoint string) (string, int, bool) {
	host, rawPort, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return "", 0, false
	}
	if addr, err := netip.ParseAddr(host); err == nil && addr.Zone() == "" {
		return addr.String(), int(port), true
	}
	return host, int(port), validDomain(host)
}

// validDomain admits only a bounded DNS name, so an arbitrary log message cannot become a journal field.
func validDomain(host string) bool { return len(host) <= 253 && hostName.MatchString(host) }

// setDestination keeps an observed numeric destination or hostname while preserving evidence already collected.
func setDestination(e *traffic.TrafficEvent, host string) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if host != e.FakeIP {
			e.Address = ip.String()
		}
	} else {
		e.Domain = host
	}
}

// finish removes a pending flow and optionally delivers its latest supported facts to the journal.
func (p *parser) finish(elm *list.Element, emit bool) {
	f := elm.Value.(*pendingFlow)
	delete(p.byID, f.contextID)
	p.order.Remove(elm)
	if emit {
		p.emit(f.event)
	}
}

// flushBefore delivers unresolved observations in ingress order, including those exactly at the cutoff.
func (p *parser) flushBefore(cutoff time.Time) {
	for elm := p.order.Front(); elm != nil; elm = p.order.Front() {
		if elm.Value.(*pendingFlow).event.Time.After(cutoff) {
			return
		}
		p.finish(elm, true)
	}
}
