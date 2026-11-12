package awg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHealthRecordPublicationIgnoresCrashLeftover verifies a stale fixed-name temporary file cannot block the next health update.
func TestHealthRecordPublicationIgnoresCrashLeftover(t *testing.T) {
	directory := t.TempDir()
	leftover := filepath.Join(directory, "health.json.next")
	if err := os.WriteFile(leftover, []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "health.json")
	updatedAt := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	if err := writeHealthRecord(path, "awg-test", os.Getuid(), os.Getgid(), 0640, updatedAt); err != nil {
		t.Fatalf("stale temporary file blocked health publication: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("health file mode is unsafe: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record healthRecord
	if err := json.Unmarshal(data, &record); err != nil || record.ID != "awg-test" || !record.UpdatedAt.Equal(updatedAt) || record.Status != "ready" {
		t.Fatalf("published health record is invalid: %+v err=%v", record, err)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Fatalf("publisher unexpectedly removed unrelated crash leftover: %v", err)
	}
}
