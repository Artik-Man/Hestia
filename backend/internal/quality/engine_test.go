package quality

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestScores follows the 1000-TCP/100-UDP acceptance example and checks empty versus failed probes.
func TestScores(t *testing.T) {
	e, err := NewEngine(filepath.Join(t.TempDir(), "checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, c := range e.settings.Checks {
		attempts, passed := 100, 98
		if c.Protocol == TCP {
			attempts, passed = 1000, 990
		}
		key := seriesKey{"fi1", c.Protocol, c.Targets[0]}
		e.record(key, now.Add(-time.Hour-time.Second), failure)
		for i := 0; i < attempts; i++ {
			k := seriesKey{"fi1", c.Protocol, c.Targets[i%len(c.Targets)]}
			result := failure
			if i < passed {
				result = success
			}
			e.record(k, now, result)
		}
		e.record(key, now, localError)
	}
	_, s := e.Snapshot([]string{"fi1", "fi2"})
	if s["fi1"].Overall == nil || *s["fi1"].Overall != 98.5 || s["fi2"].Overall != nil {
		t.Fatalf("scores %+v", s)
	}
	for _, r := range s["fi1"].Checks {
		if r.LocalErrors != 1 || r.Score == nil {
			t.Fatalf("missing check result %+v", r)
		}
	}
	// A changed check must warm up again, even if other protocols have a full sample.
	changed := e.Settings()
	changed.Checks[0].DNSName = "example.org"
	if err := e.ApplySettings(changed); err != nil {
		t.Fatal(err)
	}
	_, rows := e.Snapshot([]string{"fi1"})
	r := rows["fi1"]
	if r.Overall != nil || r.Checks[1].Samples != 1000 {
		t.Fatal(r)
	}
	k := seriesKey{"fi1", UDP, changed.Checks[0].Targets[0]}
	e.record(k, now, failure)
	_, rows = e.Snapshot([]string{"fi1"})
	if r = rows["fi1"]; r.Overall == nil || *r.Checks[0].Score != 0 {
		t.Fatal(r)
	}
}

// TestSettingsRoundTrip preserves valid settings and rejects malformed or unsafe updates without replacing the file.
func TestSettingsRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "checks.json")
	s, err := LoadSettings(p)
	if err != nil || s.WindowMinutes != 60 {
		t.Fatal(s, err)
	}
	s.WindowMinutes = 120
	if err := SaveSettings(p, s); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"127.0.0.1:53", "8.8.8.8:53", "10.0.0.1:53", "example.org:53", "1.1.1.1:54"} {
		invalid := cloneSettings(s)
		invalid.Checks[0].Targets[0] = target
		if SaveSettings(p, invalid) == nil {
			t.Fatal("accepted", target)
		}
	}
	loaded, err := LoadSettings(p)
	if err != nil || loaded.WindowMinutes != 120 || loaded.Checks[0].Targets[0] != "1.1.1.1:53" {
		t.Fatal(loaded, err)
	}
	s.Checks = []Check{}
	if err := SaveSettings(p, s); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(p); err == nil {
		t.Fatal("accepted malformed settings")
	}
}

// TestDNSProbeMatchesQuestion ignores unrelated replies, counts SERVFAIL as an exchange and sends just one query.
func TestDNSProbeMatchesQuestion(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	check := DefaultSettings().Checks[0]
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		var n int
		n, err = server.Read(buf)
		if err != nil {
			return
		}
		var m dnsmessage.Message
		if err = m.Unpack(buf[:n]); err != nil {
			return
		}
		id := m.ID
		m.ID++
		m.Response = true
		var packet []byte
		if packet, err = m.Pack(); err != nil {
			return
		}
		if _, err = server.Write(packet); err != nil {
			return
		}
		m.ID = id
		m.RCode = dnsmessage.RCodeServerFailure
		if packet, err = m.Pack(); err == nil {
			_, err = server.Write(packet)
		}
	}()
	calls := 0
	path := Path{ID: "fi1", DialContext: func(_ context.Context, n, addr string) (net.Conn, error) {
		calls++
		if n != "udp" || addr != check.Targets[0] {
			return nil, errors.New("unexpected target")
		}
		return client, nil
	}}
	got := probe(context.Background(), path, check, check.Targets[0])
	<-done
	if err != nil || got != dnsError+1 || calls != 1 {
		t.Fatalf("outcome %d attempts %d err %v", got, calls, err)
	}
}

// TestLocalSocketFailureIsNotRemoteLoss checks fail-closed handling and error classification.
func TestLocalSocketFailureIsNotRemoteLoss(t *testing.T) {
	c := DefaultSettings().Checks[1]
	if got := probe(context.Background(), Path{}, c, c.Targets[0]); got != localError {
		t.Fatalf("unexpected outcome %d", got)
	}
}

// TestPublicProbeTargets distinguishes public destinations from shared, reserved and IPv4-embedding addresses.
func TestPublicProbeTargets(t *testing.T) {
	for target, accepted := range map[string]bool{
		"100.63.255.255:443": true, "100.64.0.0:443": false, "100.127.255.255:443": false, "100.128.0.0:443": true,
		"0.0.0.1:443": false, "240.0.0.1:443": false, "198.18.0.1:443": false, "192.0.2.5:443": false,
		"[64:ff9b::7f00:1]:443": false, "[::ffff:127.0.0.1]:443": false, "[2002:7f00:1::1]:443": false,
		"[2606:4700:4700::1111]:443": true,
	} {
		s := DefaultSettings()
		s.Checks[1].Targets = []string{target}
		if (s.Validate() == nil) != accepted {
			t.Errorf("target %s accepted should be %t", target, accepted)
		}
	}
}

// TestWindowSeriesExpiry exercises multiple storage blocks, exact cutoff, all four counters and final release.
func TestWindowSeriesExpiry(t *testing.T) {
	var s windowSeries
	for i := 0; i < 512; i++ {
		s.add(time.Duration(i)*time.Nanosecond, outcome(i%4))
	}
	s.expire(257 * time.Nanosecond)
	if s.counts != [18]int{63, 64, 64, 64} {
		t.Fatal(s.counts)
	}
	s.expire(511 * time.Nanosecond)
	if s.counts != [18]int{0, 0, 0, 1} {
		t.Fatal(s.counts)
	}
	s.expire(512 * time.Nanosecond)
	if s.head != nil || s.tail != nil || s.counts != [18]int{} {
		t.Fatal("retained expired samples")
	}
}

// TestSettingsBoundHistoryBudget exercises dense short checks and rejects an excessive combined schedule.
func TestSettingsBoundHistoryBudget(t *testing.T) {
	s := DefaultSettings()
	for i := range s.Checks {
		s.Checks[i].IntervalSeconds = 1
		s.Checks[i].TimeoutSeconds = 1
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.WindowMinutes = 1440
	if s.Validate() == nil {
		t.Fatal("accepted an unbounded history schedule")
	}
	s = DefaultSettings()
	s.WindowMinutes = 1440
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

// TestResponseCodesExpireIndependently keeps DNS failures visible while all valid replies contribute successful exchanges.
func TestResponseCodesExpireIndependently(t *testing.T) {
	e, err := NewEngine(filepath.Join(t.TempDir(), "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := e.Settings()
	target := s.Checks[0].Targets[0]
	k := seriesKey{"a", UDP, target}
	now := time.Now()
	e.record(k, now.Add(-2*time.Hour), dnsError+1)
	e.record(k, now, dnsError+1) // SERVFAIL (RCODE 2)
	e.record(k, now, dnsError+2) // NXDOMAIN (RCODE 3)
	e.record(k, now, dnsError+2)
	_, scores := e.Snapshot([]string{"a"})
	row := scores["a"].Checks[0].Targets[0]
	if row.Samples != 3 || row.Successes != 3 || row.DNSErrors != 3 || len(row.DNSResponseCodes) != 2 || row.DNSResponseCodes["2"] != 1 || row.DNSResponseCodes["3"] != 2 {
		t.Fatal(row)
	}
}
