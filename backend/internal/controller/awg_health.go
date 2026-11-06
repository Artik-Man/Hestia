package controller

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/storage"
)

const (
	awgHealthMaxAge = 5 * time.Second
)

var (
	awgHealthPath = storage.Installed().AWGHealth
)

type awgHealthRecord struct {
	ActiveUnderlay string    `json:"activeUnderlay,omitempty"`
	ID             string    `json:"id"`
	UpdatedAt      time.Time `json:"updatedAt"`
	Status         string    `json:"status"`
}

// AWGHeartbeatHealthy returns true only for a fresh, root-owned, group-readable readiness record for the requested connector.
func AWGHeartbeatHealthy(id string) bool {
	_, healthy := AWGTransportHealth(id)
	return healthy
}

// AWGTransportHealth returns the active transport ID and freshness for one independently verified tunnel heartbeat.
func AWGTransportHealth(id string) (string, bool) {
	if !awg.ValidConnectionID(id) {
		return "", false
	}
	return readAWGHeartbeat(awgHealthPath+"."+id, id)
}

// readAWGHeartbeat verifies a single connector marker, rejecting stale data and unsafe files.
func readAWGHeartbeat(path, id string) (string, bool) {
	file, err := storage.OpenFile(path, storage.ReadOnly|storage.NoFollow|storage.CloseOnExec|storage.Nonblock, 0)
	if err != nil {
		return "", false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 {
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
	var record awgHealthRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", false
	}
	if !validAWGHealthRecord(record, id, time.Now()) {
		return "", false
	}
	return record.ActiveUnderlay, true
}

// validAWGHealthRecord checks connector identity, status and bounded timestamp freshness without filesystem access.
func validAWGHealthRecord(record awgHealthRecord, id string, now time.Time) bool {
	if record.ActiveUnderlay != "" && (!awg.ValidConnectionID(record.ActiveUnderlay) || record.ActiveUnderlay == id) {
		return false
	}
	if record.ID != id || record.Status != "ready" || record.UpdatedAt.IsZero() {
		return false
	}
	age := now.Sub(record.UpdatedAt)
	return age >= -time.Second && age <= awgHealthMaxAge
}
