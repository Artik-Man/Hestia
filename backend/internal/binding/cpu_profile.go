package binding

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"

	"github.com/Artik-Man/Hestia/internal/controller"
)

const cpuPprofListen = "127.0.0.1:6060"

// SetCPUProfiling transactionally toggles sing-box pprof while proving routing data remains unchanged.
func (e Engine) SetCPUProfiling(ctx context.Context, enabled bool) error {
	var currentSnapshot controller.Config
	var alreadyEnabled bool
	check := func(data []byte, staged bool) error {
		candidate, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if !staged {
			currentSnapshot = candidate
			return nil
		}
		if !reflect.DeepEqual(currentSnapshot, candidate) {
			return ErrConflict
		}
		return nil
	}
	prepare := func(stage string) error {
		profile, err := readStoredProfile(e.dir)
		if err != nil || profile.Version != 2 || profile.Inbounds == nil {
			return ErrUnavailable
		}
		alreadyEnabled = profile.Diagnostics != nil && profile.Diagnostics.CPUPprof
		currentBackend, err := os.ReadFile(filepath.Join(e.dir, "sing-box.json"))
		if err != nil {
			return ErrUnavailable
		}
		currentWithoutProfile, currentProfileEnabled, err := withoutCPUProfile(currentBackend)
		if err != nil || currentProfileEnabled != alreadyEnabled {
			return ErrUnavailable
		}
		if enabled {
			profile.Diagnostics = &diagnosticProfile{CPUPprof: true}
		} else {
			profile.Diagnostics = nil
		}
		if err := compileConnectorGeneration(ctx, e, stage, profile); err != nil {
			return err
		}
		candidateBackend, err := os.ReadFile(filepath.Join(stage, "sing-box.json"))
		if err != nil {
			return ErrUnavailable
		}
		candidateWithoutProfile, candidateProfileEnabled, err := withoutCPUProfile(candidateBackend)
		if err != nil || candidateProfileEnabled != enabled || !reflect.DeepEqual(currentWithoutProfile, candidateWithoutProfile) {
			return ErrUnavailable
		}
		return nil
	}
	return e.applyWithNoChangeCheck(ctx, prepare, check, true, func(string) (bool, error) {
		return alreadyEnabled == enabled, nil
	})
}

// withoutCPUProfile removes only the exact loopback CPU profiler option from a sing-box backend.
func withoutCPUProfile(data []byte) (any, bool, error) {
	var backend map[string]any
	if err := json.Unmarshal(data, &backend); err != nil || backend == nil {
		return nil, false, errors.New("invalid sing-box backend")
	}
	experimental, ok := backend["experimental"].(map[string]any)
	if !ok {
		return nil, false, errors.New("sing-box experimental options unavailable")
	}
	debugOption, enabled := experimental["debug"]
	if enabled {
		options, ok := debugOption.(map[string]any)
		if !ok || len(options) != 1 || options["listen"] != cpuPprofListen {
			return nil, false, errors.New("unexpected sing-box debug option")
		}
		delete(experimental, "debug")
	}
	return backend, enabled, nil
}
