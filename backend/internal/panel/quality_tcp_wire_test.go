package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Artik-Man/Hestia/internal/quality"
	"golang.org/x/net/dns/dnsmessage"
)

// tcpTestDNS records actual wire questions and replies with a fixed answer set on loopback.
type tcpTestDNS struct {
	mu        sync.Mutex
	questions []dnsmessage.Question
	address   string
}

// startTCPTestDNS binds a local UDP port, handles fixed DNS cases and stops before the test returns.
func startTCPTestDNS(t *testing.T) *tcpTestDNS {
	t.Helper()
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dns := &tcpTestDNS{address: socket.LocalAddr().String()}
	done := make(chan struct{})
	t.Cleanup(func() {
		socket.Close()
		<-done
	})
	go func() {
		defer close(done)
		var data [4096]byte
		for {
			n, peer, err := socket.ReadFrom(data[:])
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(data[:n]); err != nil || len(query.Questions) != 1 {
				t.Errorf("expected one DNS question: %+v, %v", query, err)
				return
			}
			question := query.Questions[0]
			dns.mu.Lock()
			dns.questions = append(dns.questions, question)
			dns.mu.Unlock()
			msg := tcpTestAnswer(question)
			if msg == nil {
				continue
			}
			msg.ID = query.ID
			wire, err := msg.Pack()
			if err == nil {
				_, err = socket.WriteTo(wire, peer)
			}
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	return dns
}

// tcpTestAnswer returns the designated CNAME, restricted, or NXDOMAIN response; timeout drops the packet.
func tcpTestAnswer(q dnsmessage.Question) *dnsmessage.Message {
	msg := &dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{q}}
	alias := dnsmessage.MustNewName("target.example.")
	ip := func(owner dnsmessage.Name, a [4]byte) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: a},
		}
	}
	switch strings.ToLower(q.Name.String()) {
	case "service.example.":
		msg.Answers = []dnsmessage.Resource{
			ip(dnsmessage.MustNewName("other.example."), [4]byte{9, 9, 9, 9}),
			{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
			ip(alias, [4]byte{192, 168, 1, 1}),
			ip(alias, [4]byte{8, 8, 4, 4}),
			ip(alias, [4]byte{8, 8, 8, 8}),
		}
	case "private.example.":
		msg.Answers = []dnsmessage.Resource{ip(q.Name, [4]byte{100, 64, 1, 1})}
	case "truncated.example.":
		msg.Truncated = true
	case "timeout.example.":
		return nil
	default:
		msg.RCode = dnsmessage.RCodeNameError
	}
	return msg
}

// assertQuestions drains the recorded requests and checks their names, order and IPv4 query type.
func (dns *tcpTestDNS) assertQuestions(t *testing.T, names ...string) {
	t.Helper()
	dns.mu.Lock()
	defer dns.mu.Unlock()
	var got []string
	for _, q := range dns.questions {
		if q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
			t.Errorf("unexpected question: %+v", q)
		}
		got = append(got, strings.ToLower(q.Name.String()))
	}
	if !slices.Equal(got, names) {
		t.Errorf("DNS requests: got %v, want %v", got, names)
	}
	dns.questions = nil
}

// TestTCPQualitySaveWire verifies single DNS attempts, resolved port pairs and all-or-nothing HTTP writes.
func TestTCPQualitySaveWire(t *testing.T) {
	dns := startTCPTestDNS(t)
	files := qualityFiles{settings: filepath.Join(t.TempDir(), "settings.json"), dnsServer: dns.address}
	handler := panelHandler("", "", nil, panelWrites{quality: files})
	put := func(path string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		wire, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(wire))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	putTargets := func(targets []string) *httptest.ResponseRecorder {
		return put("/api/quality/checks/TCP", quality.Check{Protocol: quality.TCP, Targets: targets, IntervalSeconds: 30, TimeoutSeconds: 3})
	}
	readFile := func() []byte {
		t.Helper()
		data, err := os.ReadFile(files.settings)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	want := []string{"1.1.1.1:443", "8.8.4.4:443", "8.8.4.4:8443", "[2606:4700:4700::1111]:443"}
	result := putTargets([]string{"1.1.1.1", "service.example", "SERVICE.EXAMPLE.:8443", "[2606:4700:4700::1111]:443"})
	if result.Code != http.StatusOK {
		t.Fatalf("PUT: HTTP %d: %s", result.Code, result.Body)
	}
	dns.assertQuestions(t, "service.example.")
	var saved quality.Settings
	if err := json.Unmarshal(result.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	for _, data := range []quality.Settings{saved, readTCPTestSettings(t, files.settings)} {
		if len(data.Checks) != 2 || data.Checks[1].Protocol != quality.TCP || !slices.Equal(data.Checks[1].Targets, want) {
			t.Fatalf("unexpected normalized settings %+v", data)
		}
	}
	if result := putTargets(want); result.Code != http.StatusOK {
		t.Fatalf("numeric re-save: %d %s", result.Code, result.Body)
	}
	dns.assertQuestions(t)
	baseline := readFile()
	for _, tc := range []struct{ host, reason string }{
		{"absent.example", "NXDOMAIN"}, {"private.example", "IPv4"},
		{"timeout.example", "тайм-аут"}, {"truncated.example", "усеч"},
	} {
		host := tc.host
		result := putTargets([]string{"8.8.8.8:444", host})
		if result.Code != http.StatusUnprocessableEntity || !strings.Contains(result.Body.String(), host) || !strings.Contains(result.Body.String(), "DNS") || !strings.Contains(result.Body.String(), tc.reason) {
			t.Errorf("expected a domain-specific DNS error for %s: HTTP %d %s", host, result.Code, result.Body)
		}
		dns.assertQuestions(t, host+".")
		if !bytes.Equal(baseline, readFile()) {
			t.Fatalf("failed save persisted a partial change for %s", host)
		}
	}
	full := quality.DefaultSettings()
	full.Checks[1].Targets = []string{"service.example:80"}
	result = put("/api/quality/settings", full)
	if result.Code != http.StatusOK {
		t.Fatalf("full PUT: %d %s", result.Code, result.Body)
	}
	dns.assertQuestions(t, "service.example.")
	if restored := readTCPTestSettings(t, files.settings); !slices.Equal(restored.Checks[1].Targets, []string{"8.8.4.4:80"}) {
		t.Fatalf("full PUT persisted incorrect targets: %+v", restored)
	}
}

// readTCPTestSettings reloads the settings exactly as the quality worker will after a successful save.
func readTCPTestSettings(t *testing.T, path string) quality.Settings {
	t.Helper()
	settings, err := quality.LoadSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	return settings
}
