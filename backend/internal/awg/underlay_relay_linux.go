package awg

import (
	"context"
	"errors"
	"github.com/Artik-Man/Hestia/internal/awgruntime"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// underlayRelay keeps the peer's local endpoint stable and drops stale replies and outbound datagrams when no candidate is selected.
type underlayRelay struct {
	local, witness          *net.UDPConn
	daemon                  netip.AddrPort
	mu                      sync.Mutex
	path, trial             *net.UDPConn
	index, slot, trialIndex int
	verified                uint64
	proofBudget             int
	signature               []int
	sampleUntil             time.Time
	prefixBytes             int
	variablePadding         bool
	ctx                     context.Context
	device, peer            string
}

// newUnderlayRelay reserves a kernel-assigned loopback port before the stored peer ever receives its configuration.
func newUnderlayRelay(slot int) (*underlayRelay, error) {
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, errors.New("cannot prepare WireGuard underlay relay")
	}
	witness, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		_ = local.Close()
		return nil, errors.New("cannot prepare WireGuard trial witness")
	}
	return &underlayRelay{local: local, witness: witness, index: -1, trialIndex: -1, slot: slot}, nil
}

// runtimeSettings replaces the validated endpoint and marks the outer socket so even a roaming peer cannot use the main route.
func (r *underlayRelay) runtimeSettings(config []byte, mark string) []byte {
	// Userspace handles local-table traffic before this terminal unreachable mark; authenticated off-relay roaming cannot recurse into the tunnel.
	lines := strings.Split(string(config), "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, "RandomTrailers = "):
			value := strings.TrimPrefix(line, "RandomTrailers = ")
			r.variablePadding = r.variablePadding || strings.EqualFold(value, "on") || value == "1"
		case strings.HasPrefix(line, "ContentPaddingAddition = "):
			value := strings.TrimPrefix(line, "ContentPaddingAddition = ")
			r.variablePadding = r.variablePadding || strings.Trim(value, "0-") != ""
		case strings.HasPrefix(line, "S4 = "):
			r.prefixBytes, _ = strconv.Atoi(strings.TrimPrefix(line, "S4 = "))
		case line == "[Interface]":
			lines[i] += "\nFwMark = " + mark
		case strings.HasPrefix(line, "Endpoint = "):
			lines[i] = "Endpoint = " + r.local.LocalAddr().String()
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// attach starts forwarding only the configured userspace daemon's UDP port to the currently selected transport listener.
func (r *underlayRelay) attach(ctx context.Context, device, peer string, listenPort []byte) error {
	port, err := strconv.ParseUint(strings.TrimSpace(string(listenPort)), 10, 16)
	if err != nil || port == 0 {
		return errors.New("cannot identify WireGuard transport socket")
	}
	r.daemon = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	r.ctx, r.device, r.peer = ctx, device, peer
	go r.forward(r.local)
	go r.forward(r.witness)
	return nil
}

// forward discards packets from other local senders and suppresses all traffic while no candidate is usable.
func (r *underlayRelay) forward(socket *net.UDPConn) {
	buffer := make([]byte, 65535)
	for {
		n, sender, err := socket.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		if sender != r.daemon {
			continue
		}
		r.mu.Lock()
		if r.trial != nil && r.takeChallenge(n) {
			_, _ = r.trial.Write(buffer[:n])
		} else if r.path != nil {
			_, _ = r.path.Write(buffer[:n])
		}
		r.mu.Unlock()
	}
}

// takeChallenge recognizes the last datagram of a freshly armed randomized DNS train under the relay lock.
func (r *underlayRelay) takeChallenge(size int) bool {
	if len(r.signature) == 0 || time.Now().After(r.sampleUntil) || size != r.signature[0] {
		return false
	}
	r.signature = r.signature[1:]
	return len(r.signature) == 0
}

// receive returns only replies from the currently selected fixed-destination forwarder to the authenticated WG socket.
func (r *underlayRelay) receive(path *net.UDPConn) {
	buffer := make([]byte, 65535)
	for {
		n, err := path.Read(buffer)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				// A restarting forwarder can briefly return ICMP port unreachable; keep the same UDP association available.
				if errors.Is(err, syscall.ECONNREFUSED) {
					continue
				}
			}
			return
		}
		r.mu.Lock()
		switch path {
		case r.path:
			_, _ = r.local.WriteToUDPAddrPort(buffer[:n], r.daemon)
		case r.trial:
			if r.proofBudget > 0 {
				r.proofBudget--
				if r.proveReply(buffer[:n]) {
					r.verified++
					r.proofBudget = 0
				}
			} else {
				_, _ = r.local.WriteToUDPAddrPort(buffer[:n], r.daemon)
			}
		}
		r.mu.Unlock()
	}
}

// proveReply lets the daemon cryptographically validate one trial datagram. The locked relay keeps backup replies from racing the UAPI observation.
func (r *underlayRelay) proveReply(packet []byte) bool {
	ctx, cancel := context.WithTimeout(r.ctx, 65*time.Millisecond)
	defer cancel()
	if runtimeDriver.Endpoint(ctx, r.device, r.peer, r.local.LocalAddr().String()) != nil {
		return false
	}
	if _, err := r.witness.WriteToUDPAddrPort(packet, r.daemon); err != nil {
		return false
	}
	for {
		out, err := runtimeDriver.Observe(ctx, awgruntime.Endpoints, r.device)
		if err != nil {
			return false
		}
		fields := strings.Fields(string(out))
		if len(fields) == 2 && fields[0] == r.peer && fields[1] == r.witness.LocalAddr().String() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Millisecond):
		}
	}
}

// selectPath retires the old UDP association before switching; -1 blocks all forwarding.
func (r *underlayRelay) selectPath(index int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if index == r.index {
		return nil
	}
	if r.path != nil {
		_ = r.path.Close()
		r.path = nil
	}
	r.index = -1
	if index < 0 {
		return nil
	}
	conn, err := r.openPath(index)
	if err != nil {
		return err
	}
	r.index, r.path = index, conn
	return nil
}

// openPath connects an ephemeral socket to one fixed forwarding port and starts its isolated return path.
func (r *underlayRelay) openPath(index int) (*net.UDPConn, error) {
	dest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000 + r.slot*128 + index}
	conn, err := net.DialUDP("udp4", nil, dest)
	if err != nil {
		return nil, errors.New("cannot select WireGuard underlay")
	}
	go r.receive(conn)
	return conn, nil
}

// probePath starts or cancels a preferred-path trial without retiring the working fallback.
func (r *underlayRelay) probePath(index int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trialIndex == index {
		return nil
	}
	if r.trial != nil {
		_ = r.trial.Close()
		r.trial = nil
	}
	r.trialIndex = -1
	if index < 0 {
		return nil
	}
	trial, err := r.openPath(index)
	if err != nil {
		return err
	}
	r.trialIndex, r.trial, r.verified = index, trial, 0
	return nil
}

// trialReplies snapshots packets cryptographically authenticated by WireGuard on the probationary path.
func (r *underlayRelay) trialReplies() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verified
}

// promoteTrial adopts the already verified association and retires the fallback after its replacement can carry peer traffic.
func (r *underlayRelay) promoteTrial() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.path != nil {
		_ = r.path.Close()
	}
	r.index, r.path = r.trialIndex, r.trial
	r.trialIndex, r.trial = -1, nil
}

// close stops the private relay and closes both sockets after the connector exits.
func (r *underlayRelay) close() {
	_ = r.probePath(-1)
	_ = r.selectPath(-1)
	_ = r.local.Close()
	_ = r.witness.Close()
}
