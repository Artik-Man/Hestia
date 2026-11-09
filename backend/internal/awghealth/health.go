package awghealth

import (
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/storage"
)

const maxAge = 35 * time.Second

var (
	healthPath        = storage.Installed().AWGHealth
	connectionPattern = regexp.MustCompile(`^(?:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|[a-z][a-z0-9-]{0,62})$`)
)

type record struct {
	ActiveUnderlay string    `json:"activeUnderlay,omitempty"`
	ID             string    `json:"id"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Status         string    `json:"status"`
}

// HeartbeatHealthy returns true only for a fresh, root-owned runtime readiness record for the named connector.
func HeartbeatHealthy(id string) bool {
	_, healthy := TransportHealth(id)
	return healthy
}

// TransportHealth reads the active transport from one fresh, verified runtime heartbeat.
func TransportHealth(id string) (string, bool) {
	if !connectionPattern.MatchString(id) {
		return "", false
	}
	return readRecord(healthPath+"."+id, id, time.Now())
}

// readRecord verifies one bounded heartbeat file without following symlinks.
func readRecord(path, id string, now time.Time) (string, bool) {
	file, err := storage.OpenFile(path, storage.ReadOnly|storage.NoFollow|storage.CloseOnExec|storage.Nonblock, 0)
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !validMode(info.Mode().Perm()) {
		return "", false
	}
	stat, ok := storage.Stat(info)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return "", false
	}
	var value record
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || !validRecord(value, id, now) {
		return "", false
	}
	return value.ActiveUnderlay, true
}

// validRecord checks connector identity, transport identity, status and bounded timestamp freshness.
func validRecord(value record, id string, now time.Time) bool {
	if value.ActiveUnderlay != "" && (!connectionPattern.MatchString(value.ActiveUnderlay) || value.ActiveUnderlay == id) {
		return false
	}
	if value.ID != id || value.Status != "ready" || value.UpdatedAt.IsZero() {
		return false
	}
	age := now.Sub(value.UpdatedAt)
	return age >= -time.Second && age <= maxAge
}
