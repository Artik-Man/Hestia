//go:build linux

package entware

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/awghealth"
	"github.com/Artik-Man/Hestia/internal/network/keeneticphysical"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/routing"
	"github.com/Artik-Man/Hestia/internal/services"
	"github.com/Artik-Man/Hestia/internal/storage"
)

const (
	smokeAPITimeout             = 500 * time.Millisecond
	selectorConvergenceTimeout  = 5 * time.Second
	selectorConvergenceInterval = 100 * time.Millisecond
	maxSnapshotSize             = 2 << 20
	maxQualitySize              = 2 << 20
	maxServiceLog               = 8 << 20
)

type backendOutbound struct {
	Tag           string `json:"tag"`
	Type          string `json:"type"`
	BindInterface string `json:"bind_interface"`
}

type backendConfig struct {
	Outbounds []backendOutbound `json:"outbounds"`
}

type smokeConfig struct {
	CountryMap     json.RawMessage   `json:"countryMap,omitempty"`
	Groups         []routing.Group   `json:"groups"`
	Lists          []routing.List    `json:"lists"`
	Healthy        map[string]bool   `json:"healthy"`
	ConnectorKinds map[string]string `json:"connectorKinds,omitempty"`
}

type selectorState struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type controllerEvent struct {
	Time           time.Time `json:"time"`
	Group          string    `json:"group"`
	SelectorTarget string    `json:"selector_target"`
}

// readManagedFile reads one bounded root-owned regular file without following symbolic links.
func readManagedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > limit {
		return nil, errors.New("managed file is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return nil, errors.New("managed file ownership is invalid")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return nil, errors.New("managed file changed during read")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("managed file exceeds its size limit")
	}
	return data, nil
}

// runSmoke validates the managed service processes, loaded generation, live selectors and optional fresh controller events.
func runSmoke(ctx context.Context, table *processTable, fresh bool) error {
	for _, kind := range []services.Kind{services.Router, services.Controller, services.BindingWatch} {
		state, err := table.status(services.Service{Kind: kind})
		if err != nil || state != services.Active {
			return errors.New("required Hestia service is not active")
		}
	}
	configPath := storage.Installed().BackendConfig
	backendBytes, err := readManagedFile(configPath, 8<<20)
	if err != nil {
		return err
	}
	backendEntry := table.entry(services.Service{Kind: services.Router})
	if backendEntry == nil || backendEntry.config != sha256.Sum256(backendBytes) {
		return errors.New("running router configuration differs from the installed generation")
	}
	snapshotPath := storage.Installed().Snapshot
	snapshotBytes, err := readManagedFile(snapshotPath, maxSnapshotSize)
	if err != nil {
		return err
	}
	config, err := decodeSnapshot(snapshotBytes)
	if err != nil {
		return errors.New("installed controller snapshot is invalid")
	}
	backend, err := decodeBackend(backendBytes)
	if err != nil {
		return errors.New("installed router configuration is invalid")
	}
	var controllerStarted time.Time
	if fresh {
		controllerEntry := table.entry(services.Service{Kind: services.Controller})
		if controllerEntry == nil {
			return errors.New("controller process handle is unavailable")
		}
		controllerStarted = controllerEntry.started
	}
	client := &http.Client{
		Timeout:       smokeAPITimeout,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	return waitForSmokeSelectors(ctx, client, "http://127.0.0.1:9090", snapshotPath, config, backend, fresh, controllerStarted)
}

// decodeSnapshot validates the controller configuration shape without importing Linux composition packages.
func decodeSnapshot(data []byte) (smokeConfig, error) {
	var config smokeConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, err
	}
	if decoder.Decode(new(any)) != io.EOF || config.Healthy == nil || len(config.Groups) == 0 {
		return config, errors.New("invalid controller snapshot")
	}
	seenGroups := make(map[string]bool)
	exits := make(map[string]bool)
	for _, group := range config.Groups {
		if group.ID == "" || seenGroups[group.ID] {
			return config, errors.New("invalid controller group")
		}
		seenGroups[group.ID] = true
		for _, id := range group.Exits {
			if id == "" || exits[id] {
				return config, errors.New("invalid controller exit")
			}
			exits[id] = true
		}
	}
	for id := range config.Healthy {
		if !exits[id] {
			return config, errors.New("snapshot references an unknown exit")
		}
	}
	decision := routing.Decide(config.Groups, config.Lists, config.Healthy, "")
	if decision.Outcome == routing.Reject || decision.Outcome == routing.RejectName {
		return config, errors.New("invalid routing snapshot")
	}
	return config, nil
}

// entry returns a process-table entry only while its retained handle remains current.
func (t *processTable) entry(service services.Service) *processEntry {
	identity, err := key(service)
	if err != nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[identity]
	if entry == nil {
		return nil
	}
	select {
	case <-entry.done:
		return nil
	default:
		return entry
	}
}

// decodeBackend strictly parses the bounded sing-box configuration used by the router process.
func decodeBackend(data []byte) (backendConfig, error) {
	var config backendConfig
	var parsed struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&parsed); err != nil {
		return config, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return config, errors.New("unexpected trailing backend content")
	}
	config.Outbounds = make([]backendOutbound, 0, len(parsed.Outbounds))
	for _, raw := range parsed.Outbounds {
		var outbound backendOutbound
		if err := json.Unmarshal(raw, &outbound); err != nil || outbound.Tag == "" || outbound.Type == "" {
			return config, errors.New("invalid backend outbound")
		}
		config.Outbounds = append(config.Outbounds, outbound)
	}
	return config, nil
}

// effectiveHealth applies only explicitly verifiable Keenetic link state and fresh AWG runtime heartbeats to the snapshot.
func effectiveHealth(config smokeConfig, backend backendConfig, awgHealthy func(string) bool) map[string]bool {
	health := make(map[string]bool, len(config.Healthy))
	for id, available := range config.Healthy {
		health[id] = available
	}
	devices := make(map[string]string)
	for _, outbound := range backend.Outbounds {
		if outbound.Tag != "deny" && outbound.Type == "direct" {
			devices[outbound.Tag] = outbound.BindInterface
		}
	}
	carrier := keeneticphysical.InstalledCarrier()
	for _, group := range config.Groups {
		for _, id := range group.Exits {
			if config.ConnectorKinds[id] == "awg" {
				health[id] = awgHealthy != nil && awgHealthy(id)
				continue
			}
			device, direct := devices[id]
			if direct && (device == "" || carrier.State(device) != panelmodel.CarrierUp) {
				health[id] = false
			}
		}
	}
	return health
}

// readQualityReport loads a fresh worker report only when it matches the installed topology generation.
func readQualityReport(snapshot string, config smokeConfig) (*panelmodel.QualityReport, error) {
	data, err := readManagedFile(storage.Installed().QualityReport, maxQualitySize)
	if errors.Is(err, os.ErrNotExist) {
		if qualityReportIsRequired(config) {
			return nil, errors.New("Hysteria 2 availability report is missing")
		}
		return nil, nil
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, errors.New("quality report is unavailable")
	}
	var report panelmodel.QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, errors.New("quality report is invalid")
	}
	captured, err := time.Parse(time.RFC3339Nano, report.CapturedAt)
	if err != nil || time.Since(captured) < 0 || time.Since(captured) > time.Minute {
		if !qualityReportIsRequired(config) {
			return nil, nil
		}
		return nil, errors.New("quality report is stale")
	}
	if len(report.Groups) != len(config.Groups) {
		if !qualityReportIsRequired(config) {
			return nil, nil
		}
		return nil, errors.New("quality report topology differs from the installed snapshot")
	}
	for i, group := range config.Groups {
		row := report.Groups[i]
		if row.ID != group.ID || len(row.Connections) != len(group.Exits) {
			if !qualityReportIsRequired(config) {
				return nil, nil
			}
			return nil, errors.New("quality report topology differs from the installed snapshot")
		}
		seen := make(map[string]bool, len(group.Exits))
		for _, connection := range row.Connections {
			if !slices.Contains(group.Exits, connection.ID) || seen[connection.ID] {
				if !qualityReportIsRequired(config) {
					return nil, nil
				}
				return nil, errors.New("quality report topology differs from the installed snapshot")
			}
			seen[connection.ID] = true
		}
	}
	snapshotInfo, err := os.Lstat(snapshot)
	if err != nil || !snapshotInfo.Mode().IsRegular() || snapshotInfo.Mode()&os.ModeSymlink != 0 || captured.Before(snapshotInfo.ModTime()) {
		if !qualityReportIsRequired(config) {
			return nil, nil
		}
		return nil, errors.New("quality report predates the installed snapshot")
	}
	return &report, nil
}

// qualityReportIsRequired reports whether smoke needs current probe results to safely select a Hysteria 2 exit.
func qualityReportIsRequired(config smokeConfig) bool {
	for _, kind := range config.ConnectorKinds {
		if kind == "hysteria2" {
			return true
		}
	}
	return false
}

// confirmedQualityTargets checks reported active choices against current health before using them.
func confirmedQualityTargets(config smokeConfig, health map[string]bool, report *panelmodel.QualityReport) (map[string]string, error) {
	selected := make(map[string]string)
	if report == nil {
		return selected, nil
	}
	for _, group := range report.Groups {
		var active []string
		for _, connection := range group.Connections {
			if config.ConnectorKinds[connection.ID] == "hysteria2" {
				health[connection.ID] = connection.Available
			}
			if connection.Active {
				active = append(active, connection.ID)
			}
		}
		if len(active) == 0 {
			continue
		}
		if len(active) != 1 || expectedTarget(routing.Group{ID: group.ID, Exits: active}, health) != active[0] {
			return nil, fmt.Errorf("quality report selected an unavailable exit")
		}
		selected[group.ID] = active[0]
	}
	return selected, nil
}

// expectedTarget returns the first configured healthy exit or the reserved deny target.
func expectedTarget(group routing.Group, health map[string]bool) string {
	if exit, outcome := routing.SelectExit(group, health); outcome == routing.Forward {
		return exit
	}
	return "deny"
}

// readLiveSelector performs a bounded local read of one selector endpoint without following redirects or proxies.
func readLiveSelector(parent context.Context, client *http.Client, endpoint, id string) (selectorState, error) {
	ctx, cancel := context.WithTimeout(parent, smokeAPITimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/proxies/"+url.PathEscape(id), nil)
	if err != nil {
		return selectorState{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return selectorState{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return selectorState{}, errors.New("router selector endpoint returned an error")
	}
	var state selectorState
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&state); err != nil {
		return selectorState{}, err
	}
	return state, nil
}

// waitForLiveSelectors retries exact selector checks while the controller converges after a transient health update.
func waitForLiveSelectors(parent context.Context, client *http.Client, endpoint string, config smokeConfig, health map[string]bool, qualityTargets map[string]string) error {
	return waitForSelectorTargets(parent, client, endpoint, config.Groups, func() (map[string]string, error) {
		return expectedSelectorTargets(config.Groups, health, qualityTargets), nil
	}, nil)
}

// waitForSmokeSelectors re-reads quality and controller evidence while the newly loaded generation converges.
func waitForSmokeSelectors(parent context.Context, client *http.Client, endpoint, snapshotPath string, config smokeConfig, backend backendConfig, fresh bool, controllerStarted time.Time) error {
	if len(config.Groups) == 0 {
		return errors.New("controller snapshot has no selector groups")
	}
	expected := func() (map[string]string, error) {
		quality, err := readQualityReport(snapshotPath, config)
		if err != nil {
			return nil, err
		}
		health := effectiveHealth(config, backend, awghealth.HeartbeatHealthy)
		qualityTargets, err := confirmedQualityTargets(config, health, quality)
		if err != nil {
			return nil, err
		}
		return expectedSelectorTargets(config.Groups, health, qualityTargets), nil
	}
	var confirmed func(map[string]string) bool
	if fresh {
		logPath := filepath.Join(storage.Installed().Runtime, "service-1.log")
		confirmed = func(targets map[string]string) bool {
			events, err := freshControllerEvents(logPath, controllerStarted)
			if err != nil {
				return false
			}
			for id, target := range targets {
				if events[id] != target {
					return false
				}
			}
			return true
		}
	}
	return waitForSelectorTargets(parent, client, endpoint, config.Groups, expected, confirmed)
}

// expectedSelectorTargets returns one live target per installed group using its latest health and quality evidence.
func expectedSelectorTargets(groups []routing.Group, health map[string]bool, qualityTargets map[string]string) map[string]string {
	targets := make(map[string]string, len(groups))
	for _, group := range groups {
		target := expectedTarget(group, health)
		if selected, ok := qualityTargets[group.ID]; ok {
			target = selected
		}
		targets[group.ID] = target
	}
	return targets
}

// waitForSelectorTargets retries until live selectors and optional controller events agree with current expectations.
func waitForSelectorTargets(parent context.Context, client *http.Client, endpoint string, groups []routing.Group, expected func() (map[string]string, error), confirmed func(map[string]string) bool) error {
	ctx, cancel := context.WithTimeout(parent, selectorConvergenceTimeout)
	defer cancel()
	lastErr := error(errors.New("router selector differs from the installed snapshot"))
	for {
		targets, err := expected()
		if err != nil {
			lastErr = err
		} else {
			matches := true
			for _, group := range groups {
				state, readErr := readLiveSelector(ctx, client, endpoint, group.ID)
				if readErr != nil || !selectorMatches(state, group, targets[group.ID]) {
					matches = false
					lastErr = errors.New("router selector differs from the installed snapshot")
					break
				}
			}
			if matches && (confirmed == nil || confirmed(targets)) {
				return nil
			}
			if matches {
				lastErr = errors.New("controller has not confirmed the current selector target")
			}
		}
		timer := time.NewTimer(selectorConvergenceInterval)
		select {
		case <-parent.Done():
			timer.Stop()
			return parent.Err()
		case <-ctx.Done():
			timer.Stop()
			if parent.Err() != nil {
				return parent.Err()
			}
			return lastErr
		case <-timer.C:
		}
	}
}

// selectorMatches requires the expected selector type, current target and configured member order.
func selectorMatches(state selectorState, group routing.Group, wanted string) bool {
	members := append(slices.Clone(group.Exits), "deny")
	return state.Type == "Selector" && state.Now == wanted && slices.Equal(state.All, members)
}

// freshControllerEvents returns the latest selector confirmation per group from this controller generation.
func freshControllerEvents(path string, started time.Time) (map[string]string, error) {
	data, err := readManagedFile(path, maxServiceLog)
	if err != nil {
		return nil, errors.New("controller log is unavailable")
	}
	confirmed := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var event controllerEvent
		if json.Unmarshal(line, &event) != nil || event.Group == "" || event.SelectorTarget == "" || event.Time.Before(started) {
			continue
		}
		confirmed[event.Group] = event.SelectorTarget
	}
	if scanner.Err() != nil {
		return nil, errors.New("controller log could not be read completely")
	}
	return confirmed, nil
}
