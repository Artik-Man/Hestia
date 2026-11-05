package dnsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"github.com/Artik-Man/Hestia/internal/dnsresolver"
	"golang.org/x/net/dns/dnsmessage"
)

// localAuthority records actual upstream UDP transactions and serves answers whose address changes at each fill.
type localAuthority struct {
	socket  *net.UDPConn
	mu      sync.Mutex
	log     map[dnsmessage.Question]int
	updated chan struct{}
}

// startAuthority starts a loopback-only UDP DNS authority whose lifetime is bound to the test.
func startAuthority(t *testing.T) *localAuthority {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	auth := &localAuthority{socket: socket, log: make(map[dnsmessage.Question]int), updated: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 65535)
		for {
			n, addr, err := socket.ReadFromUDP(packet)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(packet[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			auth.mu.Lock()
			auth.log[q]++
			serial := auth.log[q]
			auth.mu.Unlock()
			select {
			case auth.updated <- struct{}{}:
			default:
			}
			ttl := uint32(120)
			if q.Name.String() == "rotate.example." {
				ttl = 1
			}
			var body dnsmessage.ResourceBody = &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(serial)}}
			if q.Type == dnsmessage.TypeAAAA {
				body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: byte(serial)}}
			}
			query.Response = true
			query.RecursionAvailable = true
			query.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, Type: q.Type, TTL: ttl}, Body: body}}
			if reply, err := query.Pack(); err == nil {
				_, _ = socket.WriteToUDP(reply, addr)
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return auth
}

// received returns the number of wire questions for one exact name and record type.
func (a *localAuthority) received(name string, kind dnsmessage.Type) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.log[dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: kind, Class: dnsmessage.ClassINET}]
}

// waitReceived waits for an observed upstream question with a bounded timeout.
func (a *localAuthority) waitReceived(t *testing.T, name string, kind dnsmessage.Type) {
	t.Helper()
	limit := time.NewTimer(5 * time.Second)
	defer limit.Stop()
	for a.received(name, kind) == 0 {
		select {
		case <-a.updated:
		case <-limit.C:
			t.Fatalf("no upstream %s query for %s", kind, name)
		}
	}
}

// Allowed supplies the fixture's exact private transport as the only permitted DNS context.
func (a *localAuthority) Allowed(context.Context, string) ([]dnsresolver.Upstream, error) {
	return []dnsresolver.Upstream{{Exit: "fixture", Resolver: a.socket.LocalAddr().String()}}, nil
}

// Exchange sends actual packets only to the exact loopback upstream; unknown contexts fail without dialing.
func (a *localAuthority) Exchange(ctx context.Context, up dnsresolver.Upstream, packet []byte) ([]byte, error) {
	peer := a.socket.LocalAddr().(*net.UDPAddr)
	if !peer.IP.IsLoopback() || up.Exit != "fixture" || up.Resolver != peer.String() {
		return nil, errors.New("unapproved upstream")
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp4", peer.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("missing query deadline")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	reply := make([]byte, 65535)
	n, err := conn.Read(reply)
	return reply[:n], err
}

// localWorker starts both production listeners, background scheduling, heartbeat publication and cache persistence.
func localWorker(t *testing.T, store dnspolicy.Store, auth *localAuthority, dir string) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := dnsresolver.New(store, auth, filepath.Join(dir, "cache.json"))
	ready := make(chan netip.AddrPort, 1)
	done := make(chan error, 1)
	go func() {
		var wg sync.WaitGroup
		err := serve(ctx, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddr("127.0.0.1"), r, func(address netip.AddrPort) {
			wg.Add(1)
			go func() { defer wg.Done(); runWorker(ctx, r, filepath.Join(dir, "report.json")) }()
			ready <- address
		})
		cancel()
		wg.Wait()
		done <- err
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(7 * time.Second):
			t.Error("worker did not shut down")
		}
	})
	select {
	case bound := <-ready:
		t.Cleanup(stop)
		return bound.String(), stop
	case err := <-done:
		t.Fatalf("listener startup: %v", err)
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("listener did not start")
	}
	return "", nil
}

// clientAnswer sends a DNS question through the real gateway listener and validates the framed A reply.
func clientAnswer(t *testing.T, address, network, name string, id uint16) dnsmessage.Resource {
	t.Helper()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	msg := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	packet, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if network == "tcp4" {
		packet = append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)
	}
	if _, err = conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 65535)
	if network == "tcp4" {
		var size [2]byte
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			t.Fatal(err)
		}
		reply = reply[:binary.BigEndian.Uint16(size[:])]
		_, err = io.ReadFull(conn, reply)
	} else {
		var n int
		n, err = conn.Read(reply)
		reply = reply[:n]
	}
	if err != nil {
		t.Fatal(err)
	}
	var answer dnsmessage.Message
	if err = answer.Unpack(reply); err != nil || !answer.Response || answer.ID != id || answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 1 || !slices.Equal(answer.Questions, msg.Questions) {
		t.Fatalf("client reply for %s: %+v, %v", name, answer, err)
	}
	return answer.Answers[0]
}

// waitForReport polls the production reader until it accepts the heartbeat carrying the exact expected revision and membership.
func waitForReport(t *testing.T, dir string, revision int, expected []dnspolicy.DNSWarmName) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(7 * time.Second)
	defer timeout.Stop()
	var last dnspolicy.DNSWarmReport
	var err error
	for {
		last, err = dnspolicy.ReadWarmReport(filepath.Join(dir, "report.json"), time.Now())
		if err == nil && last.PolicyRevision == revision && slices.Equal(last.Automatic, expected) {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("heartbeat revision %d, names %+v: received %+v, %v", revision, expected, last, err)
		}
	}
}

// TestDNSWorkerIntegration verifies actual UDP/TCP demand, manual warming, independent exclusions, TTL rotation and disk restore.
func TestDNSWorkerIntegration(t *testing.T) {
	dir := t.TempDir()
	store := dnspolicy.Store{Path: filepath.Join(dir, "policy.json")}
	auth := startAuthority(t)
	snap, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	snap.Policy.Settings.Threshold = 2
	snap.Policy.Settings.RetentionSeconds = 30
	snap.Policy.Exclusions = []string{"rotate.example"}
	snap, err = store.Apply(snap.Revision, snap.Policy)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, stop := localWorker(t, store, auth, dir)
	const hot = "popular.example"
	first := clientAnswer(t, endpoint, "udp4", hot, 11)
	cached := clientAnswer(t, endpoint, "tcp4", hot, 12)
	if auth.received(hot, dnsmessage.TypeA) != 1 || !reflect.DeepEqual(first.Body, cached.Body) {
		t.Fatal("UDP and TCP clients did not share one upstream fill")
	}
	cold := clientAnswer(t, endpoint, "udp4", "rotate.example", 13)
	expiry := time.Now().Add(time.Duration(cold.Header.TTL) * time.Second)
	waitForReport(t, dir, snap.Revision, []dnspolicy.DNSWarmName{{Domain: hot, ClientRequests: 2}})
	time.Sleep(time.Until(expiry)) // Wait only for any unelapsed part of the wire TTL.
	rotated := clientAnswer(t, endpoint, "tcp4", "rotate.example", 14)
	if reflect.DeepEqual(cold.Body, rotated.Body) || auth.received("rotate.example", dnsmessage.TypeA) != 2 {
		t.Fatal("expired answer was not replaced with the next upstream address")
	}
	snap.Policy.Manual = []string{hot, "pinned.example"}
	snap.Policy.Exclusions = append(snap.Policy.Exclusions, hot)
	snap, err = store.Apply(snap.Revision, snap.Policy)
	if err != nil {
		t.Fatal(err)
	}
	waitForReport(t, dir, snap.Revision, nil)
	auth.waitReceived(t, "pinned.example", dnsmessage.TypeA)
	auth.waitReceived(t, hot, dnsmessage.TypeAAAA)
	if auth.received("pinned.example", dnsmessage.TypeA) != 1 || auth.received(hot, dnsmessage.TypeAAAA) != 1 || auth.received(hot, dnsmessage.TypeA) != 1 {
		t.Fatal("manual zero-demand and excluded manual names must warm each missing context once")
	}
	snap.Policy.Exclusions = []string{"rotate.example"}
	snap, err = store.Apply(snap.Revision, snap.Policy)
	if err != nil {
		t.Fatal(err)
	}
	waitForReport(t, dir, snap.Revision, []dnspolicy.DNSWarmName{{Domain: hot, ClientRequests: 2}})
	stop()
	if _, err = os.Stat(filepath.Join(dir, "report.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stopped worker left a heartbeat: %v", err)
	}
	restored, _ := localWorker(t, store, auth, dir)
	afterRestart := clientAnswer(t, restored, "tcp4", hot, 16)
	if !reflect.DeepEqual(cached.Body, afterRestart.Body) || afterRestart.Header.TTL >= cached.Header.TTL || auth.received(hot, dnsmessage.TypeA) != 1 {
		t.Fatalf("restored positive changed address/age or performed an upstream fill: cached=%+v restart=%+v", cached, afterRestart)
	}
	waitForReport(t, dir, snap.Revision, nil)
}
