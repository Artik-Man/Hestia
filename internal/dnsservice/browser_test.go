package dnsservice

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

// TestDNSWorkerPlaywright drives the shipping Angular page, policy API, DNS scheduler and actual loopback upstream together.
func TestDNSWorkerPlaywright(t *testing.T) {
	if os.Getenv("HESTIA_DNS_BROWSER_TEST") != "1" {
		t.Skip("run npm run test:browser:dns-api from frontend")
	}
	dir := t.TempDir()
	store := dnspolicy.Store{Path: filepath.Join(dir, "policy.json")}
	initial, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	initial.Policy.Settings.Threshold = 3
	initial, err = store.Apply(initial.Revision, initial.Policy)
	if err != nil {
		t.Fatal(err)
	}

	authority := startAuthority(t)
	listener, _ := localWorker(t, store, authority, dir)
	const name = "auto-only.example"
	for index := range 3 {
		clientAnswer(t, listener, "tcp4", name, uint16(index+1))
	}
	want := []dnspolicy.DNSWarmName{{Domain: name, ClientRequests: 3}}
	waitForReport(t, dir, initial.Revision, want)
	if got := authority.received(name, dnsmessage.TypeA); got != 1 {
		t.Fatalf("three incoming lookups made %d upstream queries", got)
	}

	// The child test shares only this fixture's files. It serves Angular and the real
	// policy routes on loopback. No DNS client runs while the browser edits the lists.
	ctx, cancel := context.WithTimeout(t.Context(), 105*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout=90s", "-run", "^TestDNSPanelWarmFixture$", "-v", "../panel")
	child.WaitDelay = 3 * time.Second
	qualityQuestion := dnsmessage.Message{Header: dnsmessage.Header{ID: 411, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("retry.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	packet, err := qualityQuestion.Pack()
	if err != nil {
		t.Fatal(err)
	}
	child.Env = append(os.Environ(), "HESTIA_DNS_WARM_FIXTURE_DIR="+dir, "HESTIA_DNS_WARM_LISTENER="+listener, "HESTIA_DNS_WARM_QUERY="+base64.StdEncoding.EncodeToString(packet))
	output, err := child.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatal(err)
	}
	final, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if final.Revision != initial.Revision+2 || len(final.Policy.Exclusions) != 0 || len(final.Policy.Manual) != 0 {
		t.Fatalf("unexpected final policy after two browser mutations: %+v", final)
	}
	report, err := dnspolicy.ReadWarmReport(filepath.Join(dir, "report.json"), time.Now())
	if err != nil || report.PolicyRevision != final.Revision || !slices.Equal(report.Automatic, want) {
		t.Fatalf("new demand or incorrect revision after restore: %+v, %v", report, err)
	}
}
