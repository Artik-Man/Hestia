package geoip

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestProviderWorker verifies one-shot lookups, rejected replies, key rotation, durable exact-address routing and expiry.
func TestProviderWorker(t *testing.T) {
	dir, sets := t.TempDir(), t.TempDir()
	s, err := NewEnrichment(dir, sets)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr("9.9.9.9")
	s.Observe(ip.String())
	if queued, _, _ := s.next(time.Now()); queued.IsValid() {
		t.Fatal("queried with no token")
	}
	if err = s.SetToken("test+key"); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"198.18.0.1", "fd00::1", "10.1.2.3", "api.example", "9.9.9.9", "::ffff:9.9.9.9"} {
		s.Observe(addr)
	}
	got, token, generation := s.next(time.Now())
	if got != ip || token != "test+key" {
		t.Fatal("unexpected queued address or credential")
	}
	s.Observe(ip.String())
	if queued, _, _ := s.next(time.Now()); queued.IsValid() {
		t.Fatal("duplicate or private IP queued")
	}
	status := http.StatusOK
	reply := map[string]string{"ip": ip.String(), "code": "CH"}
	leaked := false
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer dst.Close()
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token || r.URL.Path != "/"+ip.String() {
			t.Error("request did not match provider contract")
		}
		w.Header().Set("Location", dst.URL)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	defer service.Close()
	s.endpoint = service.URL + "/"
	for _, code := range []int{400, 500, 302, 429, 200} {
		status = code
		got, quota := s.lookup(t.Context(), ip, token)
		if (got == "CH") != (status == 200) || quota != (status == 429) || leaked {
			t.Fatalf("unexpected result/status %s %t %d", got, quota, status)
		}
	}
	reply["ip"] = "8.8.8.8"
	if code, _ := s.lookup(t.Context(), ip, token); code != "" {
		t.Fatal("mismatched response IP")
	}
	if err = s.SetToken("rotated"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.remember(ip, "CH", generation, now)
	if s.Country(ip.String()) != "" {
		t.Fatal("accepted reply using stale key")
	}
	s.remember(ip, "CH", s.generation, now)
	s.flush(now)
	record, err := os.ReadFile(filepath.Join(sets, "CH.json"))
	if err != nil || string(record) != `{"version":3,"rules":[{"ip_cidr":["9.9.9.9/32"]}]}` {
		t.Fatalf("route overlay: %s %v", record, err)
	}
	key, err := os.Stat(s.tokenPath)
	if err != nil || key.Mode().Perm() != 0600 {
		t.Fatal("unsafe key mode")
	}
	restored, err := NewEnrichment(dir, sets)
	if err != nil || restored.Token() != "rotated" || restored.Country(ip.String()) != "CH" {
		t.Fatalf("persisted correction: %v", err)
	}
	restored.flush(now.Add(cacheLife))
	record, err = os.ReadFile(filepath.Join(sets, "CH.json"))
	if err != nil || string(record) != `{"version":3,"rules":[]}` || restored.Country(ip.String()) != "" {
		t.Fatalf("expired route overlay: %s %v", record, err)
	}
	if err = restored.SetToken(""); err != nil || restored.Token() != "" {
		t.Fatalf("clear key: %v", err)
	}
}
