package controller

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	awgHealthPath   = "/run/hestia-awg/health.json"
	awgHealthMaxAge = 5 * time.Second
)

type awgHealthRecord struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updatedAt"`
	Status    string    `json:"status"`
}

// AWGHeartbeatHealthy returns true only for a fresh, root-owned, group-readable readiness record for the requested connector.
func AWGHeartbeatHealthy(id string) bool {
	fd, err := syscall.Open(awgHealthPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(fd), awgHealthPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0640 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return false
	}
	var record awgHealthRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF {
		return false
	}
	return validAWGHealthRecord(record, id, time.Now())
}

// validAWGHealthRecord checks connector identity, status and bounded timestamp freshness without filesystem access.
func validAWGHealthRecord(record awgHealthRecord, id string, now time.Time) bool {
	if record.ID != id || record.Status != "ready" || record.UpdatedAt.IsZero() {
		return false
	}
	age := now.Sub(record.UpdatedAt)
	return age >= -time.Second && age <= awgHealthMaxAge
}
