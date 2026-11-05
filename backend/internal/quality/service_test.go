package quality

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestServiceCheckValidation preserves saved transport settings and rejects URL escapes and malformed destinations.
func TestServiceCheckValidation(t *testing.T) {
	base := Check{IntervalSeconds: 30, TimeoutSeconds: 3}
	ping := base
	ping.Protocol = ICMP
	ping.Targets = []string{"8.8.8.8"}
	dns := base
	dns.Protocol = DNS
	dns.Targets = []string{"8.8.8.8:53"}
	dns.DNSName = "example.com"
	web := base
	web.Protocol = HTTPS
	web.Targets = []string{"8.8.8.8:443"}
	web.ServerName = "example.com"
	web.RequestPath = "/health?q=1"
	h3 := web
	h3.Protocol = HTTP3
	s := DefaultSettings()
	s.Checks = append(s.Checks, ping, dns, web, h3)
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "https://other.example/", "//other.example/", "/x#fragment", `/x\foo`} {
		bad := web
		bad.RequestPath = path
		if (Settings{WindowMinutes: 60, Checks: []Check{bad}}).Validate() == nil {
			t.Fatalf("accepted HTTP path %q", path)
		}
	}
	for _, tc := range []struct {
		check Check
		bad   string
	}{{ping, "8.8.8.8:53"}, {ping, "10.0.0.2"}, {dns, "8.8.8.8:54"}, {web, "example.com:443"}} {
		v := tc.check
		v.Targets = []string{tc.bad}
		if (Settings{WindowMinutes: 60, Checks: []Check{v}}).Validate() == nil {
			t.Errorf("accepted %s target %s", v.Protocol, tc.bad)
		}
	}
}

// TestDNSServiceScores separates valid transport replies from successful resolution of the configured A question.
func TestDNSServiceScores(t *testing.T) {
	e, err := NewEngine(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := e.Settings().Checks[0]
	app := c
	app.Protocol = DNS
	if err := e.ApplySettings(Settings{WindowMinutes: 60, Checks: []Check{c, app}}); err != nil {
		t.Fatal(err)
	}
	name := dnsmessage.MustNewName(c.DNSName + ".")
	alias := dnsmessage.MustNewName("edge.example.")
	r := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	r.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: alias, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 1, 1}}}}
	if dnsOutcome(&r, DNS) != failure {
		t.Fatal("unrelated A is not resolution")
	}
	r.Answers = append(r.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}})
	if dnsOutcome(&r, DNS) != success {
		t.Fatal("valid CNAME chain rejected")
	}
	r.RCode = dnsmessage.RCodeServerFailure
	for _, c := range []Check{c, app} {
		e.record(seriesKey{"one", c.Protocol, c.Targets[0]}, time.Now(), dnsOutcome(&r, c.Protocol))
	}
	_, scores := e.Snapshot([]string{"one"})
	got := scores["one"]
	if got.Overall == nil || *got.Overall != 50 || got.Checks[0].Successes != 1 || got.Checks[1].Successes != 0 || got.Checks[1].Samples != 1 || got.Checks[1].Targets[0].DNSResponseCodes["2"] != 1 {
		t.Fatal(got)
	}
}

// TestICMPEchoCorrelation accepts only the token issued for this exit and fails closed for SOCKS-only exits.
func TestICMPEchoCorrelation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p := Path{SocksAddress: "127.0.0.1:27000"}
	if probeICMP(ctx, p, "8.8.8.8") != localError {
		t.Fatal("SOCKS ICMP must not leak onto the default route")
	}
	c, s := net.Pipe()
	defer s.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 1500)
		n, err := s.Read(buf)
		if err != nil {
			done <- err
			return
		}
		packet, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			done <- err
			return
		}
		echo := packet.Body.(*icmp.Echo)
		packet.Type = ipv4.ICMPTypeEchoReply
		echo.Seq++
		for range 2 {
			wire, err := packet.Marshal(nil)
			if err == nil {
				_, err = s.Write(wire)
			}
			if err != nil {
				done <- err
				return
			}
			echo.Seq--
		}
		done <- nil
	}()
	p = Path{DialContext: func(_ context.Context, n, target string) (net.Conn, error) {
		if n != "ip4:icmp" || target != "8.8.8.8" {
			return nil, errors.New("wrong pin")
		}
		return c, nil
	}}
	if probeICMP(ctx, p, "8.8.8.8") != success {
		t.Fatal("matching reply not received")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestHTTPSChecksTLSAndStatus exercises a pinned GET with exact authority/path, certificate validation and redirect rejection.
func TestHTTPSChecksTLSAndStatus(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "example.com" && r.URL.RequestURI() == "/status?x=1" {
			w.WriteHeader(204)
			return
		}
		http.Redirect(w, r, "/status?x=1", 302)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	path := Path{DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		if target != "1.1.1.1:443" || network != "tcp" {
			return nil, errors.New("unexpected path")
		}
		return new(net.Dialer).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	for _, tc := range []struct {
		host, path string
		want       outcome
	}{{"example.com", "/status?x=1", success}, {"example.com", "/redirect", failure}, {"wrong.invalid", "/status?x=1", failure}} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c := Check{Protocol: HTTPS, ServerName: tc.host, RequestPath: tc.path}
		got := fetchHTTPS(ctx, path, c, "1.1.1.1:443", &tls.Config{RootCAs: roots, ServerName: tc.host, MinVersion: tls.VersionTLS12})
		cancel()
		if got != tc.want {
			t.Fatalf("%s %s: got %v want %v", tc.host, tc.path, got, tc.want)
		}
	}
}

// TestResolverTCPFallback confirms that only the DNS service check follows a truncated response via the same resolver and output.
func TestResolverTCPFallback(t *testing.T) {
	for _, protocol := range []string{UDP, DNS} {
		t.Run(protocol, func(t *testing.T) {
			c := DefaultSettings().Checks[0]
			c.Protocol = protocol
			var networks []string
			errs := make(chan error, 2)
			p := Path{DialContext: func(_ context.Context, network, target string) (net.Conn, error) {
				if target != c.Targets[0] {
					return nil, errors.New("changed target")
				}
				networks = append(networks, network)
				client, server := net.Pipe()
				go func() {
					defer server.Close()
					var n int
					var err error
					buf := make([]byte, 512)
					if network == "tcp" {
						var length [2]byte
						if _, err = io.ReadFull(server, length[:]); err != nil {
							errs <- err
							return
						}
						buf = make([]byte, binary.BigEndian.Uint16(length[:]))
						n, err = io.ReadFull(server, buf)
					} else {
						n, err = server.Read(buf)
					}
					if err != nil {
						errs <- err
						return
					}
					var reply dnsmessage.Message
					if err = reply.Unpack(buf[:n]); err != nil {
						errs <- err
						return
					}
					reply.Response = true
					reply.Truncated = network == "udp"
					if network == "tcp" {
						reply.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: reply.Questions[0].Name, Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA}, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 1, 1}}}}
					}
					wire, err := reply.Pack()
					if err == nil {
						if network == "tcp" {
							wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...)
						}
						_, err = server.Write(wire)
					}
					errs <- err
				}()
				return client, nil
			}}
			if got := probe(context.Background(), p, c, c.Targets[0]); got != success {
				t.Fatalf("probe outcome %v", got)
			}
			want := []string{"udp"}
			if protocol == DNS {
				want = append(want, "tcp")
			}
			if !slices.Equal(networks, want) {
				t.Fatalf("opened %v want %v", networks, want)
			}
			for range networks {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
