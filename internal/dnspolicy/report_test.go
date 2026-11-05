package dnspolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadWarmReport reopens atomic replacements, distinguishes a fresh empty report, and rejects corrupt or expired observations.
func TestReadWarmReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	if _, err := ReadWarmReport(path, now); err == nil {
		t.Fatal("missing report accepted")
	}
	publish := func(body string) {
		t.Helper()
		if err := os.WriteFile(path+".new", []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
	message := func(at time.Time, rows string) string {
		return fmt.Sprintf(`{"observedAt":%q,"policyRevision":0,"automatic":%s}`, at.Format(time.RFC3339Nano), rows)
	}
	const row = `{"domain":"site.example","clientRequests":5}`
	for _, bad := range []string{
		message(now.Add(-15*time.Second-time.Nanosecond), "[]"), message(now.Add(time.Second), "[]"),
		message(now, "null"), message(now, `[{"domain":"SITE.EXAMPLE","clientRequests":5}]`), message(now, `[{"domain":"127.0.0.1","clientRequests":5}]`), message(now, `[{"domain":"site.example","clientRequests":0}]`),
		message(now, "["+row+","+row+"]"), strings.Replace(message(now, "[]"), `"policyRevision":0,`, "", 1),
		message(now, "[]") + "{}", message(now, `[{"domain":"site.example","clientRequests":5,"extra":true}]`), strings.Repeat(" ", (10<<20)+1),
	} {
		publish(bad)
		if _, err := ReadWarmReport(path, now); err == nil {
			t.Fatalf("accepted invalid report of length %d", len(bad))
		}
	}
	publish(message(now.Add(-15*time.Second), "[]"))
	empty, err := ReadWarmReport(path, now)
	if err != nil || empty.Automatic == nil || len(empty.Automatic) != 0 {
		t.Fatalf("fresh empty observation rejected: %+v %v", empty, err)
	}
	publish(message(now, "["+row+"]"))
	fresh, err := ReadWarmReport(path, now)
	if err != nil || len(fresh.Automatic) != 1 || fresh.Automatic[0].ClientRequests != 5 {
		t.Fatalf("replacement after restart: %+v %v", fresh, err)
	}
}
