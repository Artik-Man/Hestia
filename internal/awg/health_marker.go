package awg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type healthRecord struct {
	ID        string    `json:"id"`
	UpdatedAt time.Time `json:"updatedAt"`
	Status    string    `json:"status"`
}

// writeHealthRecord atomically publishes a small non-secret readiness record with explicit owner, group and mode.
func writeHealthRecord(path, id string, uid, gid int, updatedAt time.Time) error {
	data, err := json.Marshal(healthRecord{ID: id, UpdatedAt: updatedAt, Status: "ready"})
	if err != nil {
		return errors.New("cannot encode AWG health record")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".health-*.tmp")
	if err != nil {
		return errors.New("cannot stage AWG health record")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chown(uid, gid); err != nil {
		_ = file.Close()
		return errors.New("cannot set AWG health record ownership")
	}
	if err := file.Chmod(0640); err != nil {
		_ = file.Close()
		return errors.New("cannot set AWG health record permissions")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("cannot write AWG health record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("cannot sync AWG health record")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close AWG health record")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("cannot publish AWG health record")
	}
	if err := syncHealthDirectory(filepath.Dir(path)); err != nil {
		return errors.New("cannot sync AWG health record directory")
	}
	return nil
}

// syncHealthDirectory flushes a health-marker directory after its atomic rename.
func syncHealthDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
