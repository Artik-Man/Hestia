package awg

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type routeManifest struct {
	ID       string `json:"id"`
	Mark     string `json:"mark"`
	Table    string `json:"table"`
	Priority string `json:"priority"`
	Device   string `json:"device"`
}

// writeRouteManifest durably publishes route ownership through a unique root-private temporary file.
func writeRouteManifest(path string, manifest routeManifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return errors.New("cannot encode AWG route ownership record")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".routes-*.tmp")
	if err != nil {
		return errors.New("cannot stage AWG route ownership record")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return errors.New("cannot secure AWG route ownership record")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("cannot write AWG route ownership record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("cannot confirm AWG route ownership record")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot confirm AWG route ownership record")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("cannot publish AWG route ownership record")
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return errors.New("cannot confirm AWG route ownership record")
	}
	return nil
}
