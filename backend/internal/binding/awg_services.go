package binding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/services"
)

// ErrAWGRuntimeUnconfirmed identifies a candidate tunnel that could not prove readiness before it became a routing exit.
var ErrAWGRuntimeUnconfirmed = errors.New("AWG runtime readiness was not confirmed")

// AWGActivationLimit bounds a save with up to 64 serial transport candidates plus gateway activation.
const AWGActivationLimit = 15 * time.Minute

// runtimeGeneration identifies the network parameters and secret consumed by a running instance.
type runtimeGeneration struct {
	slot      int
	underlays string
	config    [sha256.Size]byte
}

// readyAWG reads each ready instance from a verified generation, rejecting duplicate IDs and slots.
func readyAWG(directory string) (map[string]runtimeGeneration, error) {
	data, err := os.ReadFile(filepath.Join(directory, "profile.json"))
	if err != nil {
		return nil, ErrUnavailable
	}
	var profile struct {
		Connectors []connectorProfile `json:"connectors"`
	}
	if json.Unmarshal(data, &profile) != nil {
		return nil, ErrUnavailable
	}
	ready := make(map[string]runtimeGeneration)
	var used [awg.SlotCount]bool
	for _, c := range profile.Connectors {
		if c.Status != "ready" {
			continue
		}
		if !awg.ValidConnectionID(c.ID) || c.Slot < 0 || c.Slot >= len(used) || used[c.Slot] {
			return nil, ErrUnavailable
		}
		if _, duplicate := ready[c.ID]; duplicate {
			return nil, ErrUnavailable
		}
		secret, err := os.ReadFile(filepath.Join(directory, awgTreeName, c.ID, "profile.conf"))
		if err != nil {
			return nil, ErrUnavailable
		}
		ready[c.ID] = runtimeGeneration{underlays: strings.Join(c.Underlays, "\x00"), slot: c.Slot, config: sha256.Sum256(secret)}
		used[c.Slot] = true
	}
	return ready, nil
}

// runtimeChange names an instance whose own configuration changed and the slot that it owns.
type runtimeChange struct {
	id   string
	slot int
}

// runtimePlan lists the only instances requiring a stop, and whether the live router can keep its exact loaded generation.
type runtimePlan struct {
	changes      []runtimeChange
	sameTopology bool
}

// planInstances compares immutable journal generations, even after a partial publication of the installed files.
func (e Engine) planInstances(journal string, routingOnly bool) (runtimePlan, error) {
	var plan runtimePlan
	if routingOnly {
		return plan, nil
	}
	previous := filepath.Join(journal, "previous")
	for _, path := range []string{journal, previous} {
		if err := privateDirectory(path); err != nil {
			return plan, err
		}
		if err := e.validateGeneration(path, path == previous); err != nil {
			return plan, err
		}
		if err := verifyAWGTreeDigest(path); err != nil {
			return plan, err
		}
	}
	before, err := readyAWG(previous)
	if err != nil {
		return plan, err
	}
	after, err := readyAWG(journal)
	if err != nil {
		return plan, err
	}
	stable := len(before) == len(after)
	for id, old := range before {
		next, ok := after[id]
		if !ok || next.slot != old.slot {
			stable = false
		}
		if !ok || old != next {
			plan.changes = append(plan.changes, runtimeChange{id, old.slot})
		}
	}
	for id, added := range after {
		if _, ok := before[id]; !ok {
			plan.changes = append(plan.changes, runtimeChange{id, added.slot})
		}
	}
	slices.SortFunc(plan.changes, func(a, b runtimeChange) int { return strings.Compare(a.id, b.id) })
	if !stable || len(plan.changes) == 0 {
		return plan, nil
	}
	for _, file := range []string{"snapshot.json", "sing-box.json"} {
		left, err := os.ReadFile(filepath.Join(previous, file))
		if err != nil {
			return plan, err
		}
		right, err := os.ReadFile(filepath.Join(journal, file))
		if err != nil {
			return plan, err
		}
		if !bytes.Equal(left, right) {
			return plan, nil
		}
	}
	plan.sameTopology = true
	return plan, nil
}

// guarded checks the exact kernel guards for every changed instance, with a fake boundary for non-Linux tests.
func (e Engine) guarded(ctx context.Context, changes []runtimeChange) bool {
	check := e.guardCheck
	if check == nil {
		check = awg.ConfirmConnectorGuards
	}
	for _, change := range changes {
		if check(ctx, change.id, change.slot) != nil {
			return false
		}
	}
	return true
}

// stop preserves the shared router only when its inputs stay identical and both IP families remain guarded.
// Otherwise it drains the router before retiring the changed instances' policy state.
func (e Engine) stop(ctx context.Context, journal string, routingOnly bool) (runtimePlan, error) {
	plan, err := e.planInstances(journal, routingOnly)
	preserve := err == nil && plan.sameTopology && e.guarded(ctx, plan.changes) && e.serviceActive(ctx, services.Router) && e.serviceActive(ctx, services.Controller)
	if !preserve {
		if stopErr := e.serviceManager().Stop(ctx, services.Service{Kind: services.Controller}, services.Service{Kind: services.Router}); stopErr != nil {
			return plan, errors.Join(err, stopErr)
		}
	}
	if err != nil {
		return plan, err
	}
	for _, change := range plan.changes {
		if err := e.serviceManager().Stop(ctx, services.Service{Kind: services.AWG, Instance: change.id}); err != nil {
			return plan, err
		}
	}
	if preserve && !e.guarded(ctx, plan.changes) {
		preserve = false
		if err := e.serviceManager().Stop(ctx, services.Service{Kind: services.Controller}, services.Service{Kind: services.Router}); err != nil {
			return plan, err
		}
	}
	if !preserve {
		for _, change := range plan.changes {
			if err := awg.RetireStoppedConnector(ctx, change.id, change.slot, false); err != nil {
				return plan, err
			}
		}
	}
	plan.sameTopology = preserve
	return plan, nil
}

// startVerified confirms real tunnel egress before committing. Manual transports need the guarded backend to reach their peer.
func (e Engine) startVerified(ctx context.Context, plan runtimePlan) error {
	ready, err := readyAWG(e.dir)
	if err != nil {
		return err
	}
	var awaiting []runtimeChange
	for _, change := range plan.changes {
		runtime, exists := ready[change.id]
		if !exists {
			continue
		}
		if err := e.startInstance(ctx, change.id, true); err != nil {
			return errors.Join(ErrAWGRuntimeUnconfirmed, err)
		}
		if runtime.underlays != "" && !plan.sameTopology {
			if err := e.waitInstanceGuards(ctx, change); err != nil {
				return errors.Join(ErrAWGRuntimeUnconfirmed, err)
			}
			awaiting = append(awaiting, change)
		} else if err := e.waitForAWGReady(ctx, change.id, ready[change.id]); err != nil {
			return errors.Join(ErrAWGRuntimeUnconfirmed, err)
		}
	}
	if len(awaiting) > 0 {
		if err := e.serviceManager().Start(ctx, services.Service{Kind: services.Router}); err != nil {
			return err
		}
		for _, change := range awaiting {
			if err := e.waitForAWGReady(ctx, change.id, ready[change.id]); err != nil {
				return errors.Join(ErrAWGRuntimeUnconfirmed, err)
			}
		}
	}
	if plan.sameTopology {
		return e.serviceManager().Start(ctx, services.Service{Kind: services.SmokeCurrent})
	}
	if err := e.serviceManager().Start(ctx, services.Service{Kind: services.Router}, services.Service{Kind: services.Controller}); err != nil {
		return err
	}
	return e.verify(ctx)
}

// startInstance starts one trusted service, optionally discarding a prior readiness marker for a newly published generation.
func (e Engine) startInstance(ctx context.Context, id string, fresh bool) error {
	installed, err := e.awgUnitInstalled()
	if err != nil || !installed {
		return ErrUnavailable
	}
	if fresh {
		if err := clearAWGReadyMarker(id); err != nil {
			return err
		}
	}
	return e.serviceManager().Start(ctx, services.Service{Kind: services.AWG, Instance: id})
}

// waitInstanceGuards permits backend startup only once both address families block traffic escaping this slot.
func (e Engine) waitInstanceGuards(ctx context.Context, change runtimeChange) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticks := time.NewTicker(250 * time.Millisecond)
	defer ticks.Stop()
	for {
		if e.guarded(ctx, []runtimeChange{change}) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticks.C:
		}
	}
}

// startBootInstance releases recovery once a manual transport is guarded so its backend can contact the peer.
func (e Engine) startBootInstance(ctx context.Context, id string, runtime runtimeGeneration) error {
	change := runtimeChange{id, runtime.slot}
	if err := e.startInstance(ctx, id, false); err != nil {
		return err
	}
	if runtime.underlays != "" {
		return e.waitInstanceGuards(ctx, change)
	}
	err := e.waitForAWGReady(ctx, id, runtime)
	if err != nil && ctx.Err() == nil && e.guarded(ctx, []runtimeChange{change}) {
		return nil
	}
	return err
}

// awgUnitInstalled delegates template validation to the selected platform, retaining the public binding error.
func (e Engine) awgUnitInstalled() (bool, error) {
	if e.unitCheck != nil {
		return e.unitCheck()
	}
	installed, err := e.serviceManager().AWGTemplateInstalled()
	if err != nil {
		return false, ErrUnavailable
	}
	return installed, nil
}

// waitAWGReady waits for the root service's private marker written only after handshake and bound egress verification.
func waitAWGReady(ctx context.Context, id string, timeout time.Duration) error {
	deadline := time.NewTicker(100 * time.Millisecond)
	defer deadline.Stop()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		info, err := os.Lstat(awgReady + "." + id)
		stat, ok := infoStat(info)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && info.Size() == 6 && ok && int(stat.Uid) == 0 && stat.Nlink == 1 {
			data, readErr := os.ReadFile(awgReady + "." + id)
			if readErr == nil && string(data) == "ready\n" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("AWG service did not confirm its bound egress probe")
		case <-deadline.C:
		}
	}
}

// waitForAWGReady delegates readiness checks to a fakeable boundary while production requires the private service marker.
func (e Engine) waitForAWGReady(ctx context.Context, id string, runtime runtimeGeneration) error {
	if e.readyWait != nil {
		return e.readyWait(ctx, id)
	}
	// Each manual candidate can consume two inner-probe deadlines plus two candidate rounds.
	timeout := 25 * time.Second
	if runtime.underlays != "" {
		timeout += time.Duration(1+strings.Count(runtime.underlays, "\x00")) * 12 * time.Second
	}
	return waitAWGReady(ctx, id, timeout)
}

// clearAWGReadyMarker removes only a prior root-owned readiness file before starting a fresh connector generation.
func clearAWGReadyMarker(id string) error {
	info, err := os.Lstat(awgReady + "." + id)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	stat, ok := infoStat(info)
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(stat.Uid) != 0 || stat.Nlink != 1 {
		return ErrUnavailable
	}
	if err := os.Remove(awgReady + "." + id); err != nil {
		return ErrUnavailable
	}
	return nil
}

// startAWGForBoot restores all committed ready tunnels before systemd starts the shared backend.
func (e Engine) startAWGForBoot(ctx context.Context) error {
	ready, err := readyAWG(e.dir)
	if err != nil || len(ready) == 0 {
		return err
	}
	if err := e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.Validate, Source: e.dir}); err != nil {
		return ErrUnavailable
	}
	ids := make([]string, 0, len(ready))
	for id := range ready {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	results := make(chan error, len(ids))
	for _, id := range ids {
		go func() { results <- e.startBootInstance(ctx, id, ready[id]) }()
	}
	var failures []error
	for range ids {
		failures = append(failures, <-results)
	}
	return errors.Join(failures...)
}
