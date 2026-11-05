package binding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

const connectorTestConfig = `[Interface]
Address = 10.66.66.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
DNS = 1.1.1.1

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
`

// TestAWGEngineCreateUpdateDelete covers committed activation, same-ID updates, and removal through one profile journal.
func TestAWGEngineCreateUpdateDelete(t *testing.T) {
	e := connectorTestEngine(t)
	request := panelmodel.AWGSaveRequest{ID: "awg-one", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), request, false); err != nil {
		t.Fatalf("create connector failed: %v", err)
	}
	profile, err := readStoredProfile(e.dir)
	if err != nil || profile.Version != 2 || len(profile.Connectors) != 1 || profile.Connectors[0].Status != "ready" || profile.Groups[0].Exits[0] != request.ID {
		t.Fatalf("created profile generation is not ready: %#v, %v", profile, err)
	}
	updated := request
	updated.Group, updated.Priority = "ru", 1
	updated.Profile = strings.Replace(connectorTestConfig, "10.66.66.2/32", "10.66.66.3/32", 1)
	if err := e.ApplyAWG(context.Background(), updated, true); err != nil {
		t.Fatalf("same-ID update failed: %v", err)
	}
	profile, err = readStoredProfile(e.dir)
	if err != nil || profile.Connectors[0].Group != "ru" || profile.Connectors[0].Priority != 1 || profile.Groups[1].Exits[0] != request.ID {
		t.Fatalf("updated profile generation is inconsistent: %#v, %v", profile, err)
	}
	if err := e.DeleteAWG(context.Background(), request.ID); err != nil {
		t.Fatalf("delete connector failed: %v", err)
	}
	profile, err = readStoredProfile(e.dir)
	if err != nil || len(profile.Connectors) != 0 || len(profile.Groups[1].Exits) != 0 {
		t.Fatalf("deleted connector remains in profile: %#v, %v", profile, err)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, awgTreeName, request.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted connector secrets remain in the active tree: %v", err)
	}
}

// TestAWGOmittedPosition reads the latest order under the transaction lock and appends new members.
func TestAWGOmittedPosition(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	for _, id := range []string{"one", "two"} {
		if err := e.ApplyAWG(ctx, panelmodel.AWGSaveRequest{ID: id, Group: "fi", Profile: connectorTestConfig}, false); err != nil {
			t.Fatal(err)
		}
	}
	p, err := readStoredProfile(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	exits := p.Groups[0].Exits
	if len(exits) < 2 || !slices.Equal(exits[len(exits)-2:], []string{"one", "two"}) {
		t.Fatalf("append order: %v", exits)
	}
	if err := e.ApplyAWG(ctx, panelmodel.AWGSaveRequest{ID: "two", Group: "ru", Priority: 1, Profile: connectorTestConfig}, true); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyAWG(ctx, panelmodel.AWGSaveRequest{ID: "two", Profile: connectorTestConfig}, true); err != nil {
		t.Fatal(err)
	}
	saved, err := e.ReadAWGProfile("two")
	if err != nil || saved.Group != "ru" || saved.Priority != 1 {
		t.Fatalf("edit lost moved position: group=%s priority=%d err=%v", saved.Group, saved.Priority, err)
	}
}

// TestAWGStage1CompilerLifecycle verifies both generations against the production compiler and the shipped direct/TUN profile.
func TestAWGStage1CompilerLifecycle(t *testing.T) {
	e := connectorTestEngine(t)
	compiler := filepath.Join("..", "..", "..", "deploy", "profile.py")
	base := mustReadTestFile(t, filepath.Join("..", "..", "..", "deploy", "scheme3", "guest-profile.json"))
	if err := os.WriteFile(filepath.Join(e.dir, "profile.json"), base, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"snapshot.json", "sing-box.json"} {
		if err := os.Remove(filepath.Join(e.dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	fakeRun := e.run
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name != python || len(args) < 2 || args[1] != profile {
			return fakeRun(ctx, name, args...)
		}
		args[1] = compiler
		return exec.CommandContext(ctx, "python3", args...).Run()
	}
	ctx := context.Background()
	if err := e.run(ctx, python, "-I", profile, filepath.Join(e.dir, "profile.json"), e.dir, e.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(e.dir, "snapshot.json"), 0640); err != nil {
		t.Fatal(err)
	}
	writeTestDigests(t, e.dir)
	request := panelmodel.AWGSaveRequest{ID: "awg-trial", Group: "default", Priority: 2, Profile: connectorTestConfig}
	if err := e.ApplyAWG(ctx, request, false); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := e.CreateGroup(ctx, "keenetic-direct"); !errors.Is(err, ErrConflict) {
		t.Fatalf("existing exit should conflict: %v", err)
	}
	if err := e.CreateGroup(ctx, "reserve"); err != nil {
		t.Fatalf("create group alongside active AWG: %v", err)
	}
	if err := e.run(ctx, python, "-I", profile, "--validate-managed", e.dir); err != nil {
		t.Fatalf("new group generation invalid: %v", err)
	}
	current, err := readStoredProfile(e.dir)
	if err != nil || len(current.Connectors) != 1 || current.Connectors[0].Status != "ready" ||
		len(current.Groups) != 2 || current.Groups[1].ID != "reserve" || current.Groups[1].DefaultExit != "deny" ||
		current.Groups[1].Exits == nil || len(current.Groups[1].Exits) != 0 {
		t.Fatalf("group creation did not preserve the ready connector and append an empty group: %v", err)
	}
	newID, err := e.CreateNamedGroup(ctx, "Офис Москва")
	if err != nil || !regexp.MustCompile(`^g-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(newID) {
		t.Fatalf("create named group returned %q: %v", newID, err)
	}
	before := mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json"))
	if err := e.RenameGroup(ctx, "default", "Домашняя сеть"); err != nil {
		t.Fatal(err)
	}
	var oldBackend, newBackend map[string]any
	if err := json.Unmarshal(before, &oldBackend); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json")), &newBackend); err != nil || !reflect.DeepEqual(oldBackend, newBackend) {
		t.Fatal("display name changed backend routing settings")
	}
	if err := e.RenameGroup(ctx, newID, "Домашняя сеть"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate display name: %v", err)
	}
	if err := e.CreateGroup(ctx, "default"); !errors.Is(err, ErrConflict) {
		t.Errorf("routing ID collision: %v", err)
	}
	if err := e.DeleteGroup(ctx, newID); err != nil {
		t.Fatalf("delete empty named group: %v", err)
	}
	if err := e.DeleteGroup(ctx, newID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted group remains active: %v", err)
	}
	secretPath := filepath.Join(e.dir, awgTreeName, request.ID, "profile.conf")
	secretBefore := string(mustReadTestFile(t, secretPath))
	if err := e.MoveExit(ctx, "keenetic-direct", "default", "reserve", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.MoveExit(ctx, "keenetic-direct", "default", "reserve", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale move accepted: %v", err)
	}
	if err := e.MoveExit(ctx, request.ID, "default", "reserve", 3); !errors.Is(err, ErrInvalidOrder) {
		t.Fatalf("out-of-range priority accepted: %v", err)
	}
	if err := e.ApplyOrder(ctx, panelmodel.GroupOrderChange{
		Expected: []panelmodel.OrderedGroup{{ID: "default", Exits: []string{request.ID}}, {ID: "reserve", Exits: []string{"keenetic-direct"}}},
		Groups:   []panelmodel.OrderedGroup{{ID: "default", Exits: []string{}}, {ID: "reserve", Exits: []string{request.ID, "keenetic-direct"}}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.run(ctx, python, "-I", profile, "--validate-managed", e.dir); err != nil {
		t.Fatalf("moved generation invalid: %v", err)
	}
	moved, err := readStoredProfile(e.dir)
	if err != nil || len(moved.Groups[0].Exits) != 0 || moved.Groups[0].DefaultExit != "deny" ||
		!reflect.DeepEqual(moved.Groups[1].Exits, []string{request.ID, "keenetic-direct"}) ||
		len(moved.Connectors) != 1 || moved.Connectors[0].Priority != 1 || moved.Connectors[0].Group != "reserve" ||
		moved.Connectors[0].Status != "ready" || string(mustReadTestFile(t, secretPath)) != secretBefore {
		t.Fatalf("move changed connector or group semantics: %v", err)
	}
	if err := e.MoveExit(ctx, "keenetic-direct", "reserve", "default", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteAWG(ctx, request.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := e.run(ctx, python, "-I", profile, "--validate-managed", e.dir); err != nil {
		t.Fatalf("deleted generation invalid: %v", err)
	}
	final, err := readStoredProfile(e.dir)
	if err != nil || len(final.Connectors) != 0 || len(final.Groups) != 2 || final.Groups[0].Name != "Домашняя сеть" || final.Groups[1].ID != "reserve" || final.Groups[0].DefaultExit != "keenetic-direct" {
		t.Fatalf("did not restore direct generation: %v", err)
	}
}

// TestStoredProfileInboundMode preserves the distinction between an empty managed inbound list and SOCKS profiles without inbounds.
func TestStoredProfileInboundMode(t *testing.T) {
	for _, source := range []string{`{"version":2,"inbounds":[]}`, `{"version":2,"socks_port":1080}`} {
		var input storedProfile
		if err := json.Unmarshal([]byte(source), &input); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		if input.Inbounds == nil && result["inbounds"] != nil || input.Inbounds != nil && string(result["inbounds"]) != "[]" {
			t.Fatalf("unexpected inbounds for %s: %s", source, result["inbounds"])
		}
	}
}

// TestAWGEngineDeleteFirstRenumbersRemainingConnector deletes the first of two group exits and keeps the remaining profile metadata aligned.
func TestAWGEngineDeleteFirstRenumbersRemainingConnector(t *testing.T) {
	e := connectorTestEngine(t)
	first := panelmodel.AWGSaveRequest{ID: "awg-one", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), first, false); err != nil {
		t.Fatalf("create first connector failed: %v", err)
	}
	second := panelmodel.AWGSaveRequest{ID: "awg-two", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), second, false); err != nil {
		t.Fatalf("create second connector failed: %v", err)
	}
	if err := e.DeleteAWG(context.Background(), second.ID); err != nil {
		t.Fatalf("delete first group exit failed: %v", err)
	}
	profile, err := readStoredProfile(e.dir)
	if err != nil || len(profile.Connectors) != 1 || profile.Connectors[0].ID != first.ID || profile.Connectors[0].Priority != 1 || profile.Groups[0].Exits[0] != first.ID {
		t.Fatalf("remaining connector priority is inconsistent: %#v, %v", profile, err)
	}
	metadataData, err := os.ReadFile(filepath.Join(e.dir, awgTreeName, first.ID, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal(metadataData, &metadata); err != nil || metadata.Priority != 1 {
		t.Fatalf("remaining connector metadata was not renumbered: %+v, %v", metadata, err)
	}
}

// TestAWGEngineConflictAndActivationRollback rejects duplicate IDs and restores all files and secrets on probe failure.
func TestAWGEngineConflictAndActivationRollback(t *testing.T) {
	e := connectorTestEngine(t)
	request := panelmodel.AWGSaveRequest{ID: "awg-one", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), request, false); err != nil {
		t.Fatalf("initial create failed: %v", err)
	}
	oldProfile, err := os.ReadFile(filepath.Join(e.dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, err := os.ReadFile(filepath.Join(e.dir, awgTreeName, request.ID, "profile.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyAWG(context.Background(), request, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate create was not rejected: %v", err)
	}
	baseRun := e.run
	serviceFailed := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == systemctl && len(args) >= 2 && args[0] == "start" && args[1] == instanceUnit(request.ID) && !serviceFailed {
			serviceFailed = true
			return errors.New("simulated connector service failure")
		}
		return baseRun(ctx, name, args...)
	}
	serviceUpdate := request
	serviceUpdate.Profile = strings.Replace(connectorTestConfig, "10.66.66.2/32", "10.66.66.8/32", 1)
	if err := e.ApplyAWG(context.Background(), serviceUpdate, true); err == nil || !serviceFailed {
		t.Fatal("connector service failure was committed")
	}
	profileAfterServiceFailure, err := os.ReadFile(filepath.Join(e.dir, "profile.json"))
	if err != nil || string(profileAfterServiceFailure) != string(oldProfile) {
		t.Fatalf("service failure did not restore the profile: %v", err)
	}
	probeFailed := false
	e.readyWait = func(context.Context, string) error {
		if !probeFailed {
			probeFailed = true
			return errors.New("simulated AWG probe failure")
		}
		return nil
	}
	update := request
	update.Profile = strings.Replace(connectorTestConfig, "10.66.66.2/32", "10.66.66.9/32", 1)
	if err := e.ApplyAWG(context.Background(), update, true); err == nil {
		t.Fatal("unverified connector update was committed")
	}
	profile, err := os.ReadFile(filepath.Join(e.dir, "profile.json"))
	if err != nil || string(profile) != string(oldProfile) {
		t.Fatalf("profile rollback failed: %v", err)
	}
	secret, err := os.ReadFile(filepath.Join(e.dir, awgTreeName, request.ID, "profile.conf"))
	if err != nil || string(secret) != string(oldSecret) {
		t.Fatalf("secret rollback failed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful rollback did not retire the journal: %v", err)
	}
}

// connectorTestEngine prepares a valid v1 base generation and fakes only compiler, systemd, sing-box, and egress readiness.
func connectorTestEngine(t *testing.T) Engine {
	t.Helper()
	e := testEngine(t)
	profileData := []byte(`{"version":1,"interfaces":[],"groups":[{"id":"fi","exits":[]},{"id":"ru","exits":[]}],"lists":[],"healthy":{},"socks_port":1080}`)
	snapshotData := []byte(`{"groups":[{"id":"fi","exits":[]},{"id":"ru","exits":[]}],"lists":[],"healthy":{}}`)
	if err := os.WriteFile(filepath.Join(e.dir, "profile.json"), profileData, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "snapshot.json"), snapshotData, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "sing-box.json"), []byte(`{"outbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	writeTestDigests(t, e.dir)
	e.unitCheck = func() (bool, error) { return true, nil }
	e.readyWait = func(context.Context, string) error { return nil }
	e.guardCheck = func(context.Context, string, int) error { return nil }
	e.run = func(_ context.Context, name string, args ...string) error {
		if name == python && len(args) > 2 && args[1] == profile {
			if args[2] == "--validate-managed" || args[2] == "--current" {
				return nil
			}
			var candidate storedProfile
			if err := json.Unmarshal(mustReadTestFile(t, args[2]), &candidate); err != nil {
				return err
			}
			stage := args[3]
			snapshot, err := json.Marshal(struct {
				Groups  []connectorGroup `json:"groups"`
				Lists   any              `json:"lists"`
				Healthy map[string]bool  `json:"healthy"`
			}{Groups: candidate.Groups, Lists: candidate.Lists, Healthy: candidate.Healthy})
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(stage, "snapshot.json"), snapshot, 0600); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(stage, "sing-box.json"), []byte(`{"outbounds":[]}`), 0600); err != nil {
				return err
			}
			return nil
		}
		return nil
	}
	return e
}

// mustReadTestFile reads a fixture path or fails the current test immediately.
func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestAWGSecondTunnelPreservesFirst checks that concurrent ready connectors survive a neighboring mutation and a failed replacement.
func TestAWGSecondTunnelPreservesFirst(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	first := panelmodel.AWGSaveRequest{ID: "awg-first", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	second := panelmodel.AWGSaveRequest{ID: "awg-second", Group: "ru", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(ctx, first, false); err != nil {
		t.Fatal(err)
	}
	run := e.run
	preserveBackend := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if preserveBackend && name == systemctl && args[0] == "stop" && slices.Contains(args, router) {
			t.Fatal("secret-only update interrupted the shared backend")
		}
		if name == systemctl && strings.Contains(strings.Join(args, " "), "hestia-awg@awg-first.service") {
			t.Fatal("neighboring transaction touched the first connector unit")
		}
		return run(ctx, name, args...)
	}
	if err := e.ApplyAWG(ctx, second, false); err != nil {
		t.Fatal(err)
	}
	current, err := readStoredProfile(e.dir)
	if err != nil || len(current.Connectors) != 2 || !current.Healthy[first.ID] || !current.Healthy[second.ID] {
		t.Fatalf("expected two ready connectors: %v", err)
	}
	failed := false
	e.readyWait = func(context.Context, string) error {
		if !failed {
			failed = true
			return errors.New("second handshake failed")
		}
		return nil
	}
	preserveBackend = true
	second.Profile = strings.Replace(second.Profile, "10.66.66.2", "10.66.66.3", 1)
	if err := e.ApplyAWG(ctx, second, true); err == nil || !failed {
		t.Fatal("failed replacement was accepted")
	}
	preserveBackend = false
	if err := e.DeleteAWG(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
}

// TestAWGRollbackAfterPartialPublication checks watchdog recovery from a crash between publishing profile.json and the private tree.
func TestAWGRollbackAfterPartialPublication(t *testing.T) {
	for _, scenario := range []struct {
		label     string
		move      bool
		guards    bool
		wantDrain bool
	}{
		{"changed-group", true, true, true},
		{"same-group-guarded", false, true, false},
		{"same-group-missing-guard", false, false, true},
	} {
		t.Run(scenario.label, func(t *testing.T) {
			e := connectorTestEngine(t)
			ctx := context.Background()
			one := panelmodel.AWGSaveRequest{ID: "one", Group: "fi", Priority: 1, Profile: connectorTestConfig}
			two := panelmodel.AWGSaveRequest{ID: "two", Group: "ru", Priority: 1, Profile: connectorTestConfig}
			for _, request := range []panelmodel.AWGSaveRequest{one, two} {
				if err := e.ApplyAWG(ctx, request, false); err != nil {
					t.Fatal(err)
				}
			}
			stage, err := os.MkdirTemp(e.dir, ".test-stage-")
			if err != nil {
				t.Fatal(err)
			}
			if err := e.stageAWGTree(stage); err != nil {
				t.Fatal(err)
			}
			two.Profile = strings.Replace(two.Profile, "10.66.66.2", "10.66.66.3", 1)
			if scenario.move {
				two.Priority, two.Group = 2, "fi"
			}
			parsed, err := awg.Parse([]byte(two.Profile))
			if err != nil {
				t.Fatal(err)
			}
			if err := stageAWGChange(ctx, e, stage, two, parsed, true); err != nil {
				t.Fatal(err)
			}
			if err := e.publishJournal(stage); err != nil {
				t.Fatal(err)
			}
			journal := filepath.Join(e.dir, pending)
			if err := os.WriteFile(filepath.Join(e.dir, "profile.json"), mustReadTestFile(t, filepath.Join(journal, "profile.json")), 0600); err != nil {
				t.Fatal(err)
			}
			var units []string
			drained := false
			e.guardCheck = func(context.Context, string, int) error {
				if !scenario.guards {
					return errors.New("guard unavailable")
				}
				return nil
			}
			e.run = func(ctx context.Context, name string, args ...string) error {
				if name == systemctl && args[0] == "stop" && slices.Contains(args, router) {
					drained = true
				}
				if name == systemctl && len(args) == 2 && strings.HasPrefix(args[1], "hestia-awg@") {
					units = append(units, args[0]+" "+args[1])
				}
				return nil
			}
			if err := e.WatchPending(ctx); err != nil {
				t.Fatal(err)
			}
			if drained != scenario.wantDrain {
				t.Fatalf("backend drain=%v", drained)
			}
			if !reflect.DeepEqual(units, []string{"stop hestia-awg@two.service", "start hestia-awg@two.service"}) {
				t.Fatalf("wrong recovery units: %v", units)
			}
			current, err := readStoredProfile(e.dir)
			if err != nil || len(current.Connectors) != 2 || current.Connectors[1].Slot != 1 || current.Connectors[1].Group != "ru" || !current.Healthy["one"] || !current.Healthy["two"] {
				t.Fatalf("committed connector assignments were not restored: %v", err)
			}
		})
	}
}

// TestAWGAllocationMigratesLegacyConfigured checks overlapping legacy zero slots, stable assignments and bounded exhaustion.
func TestAWGAllocationMigratesLegacyConfigured(t *testing.T) {
	connectors := []connectorProfile{{ID: "legacy", Status: "configured"}, {ID: "active", Status: "ready"}}
	for _, check := range []struct {
		id   string
		slot int
	}{{"active", 0}, {"legacy", 1}, {"new", 1}} {
		slot, err := allocateConnectorSlot(connectors, check.id)
		if err != nil || slot != check.slot {
			t.Fatalf("slot for %s = %d, %v", check.id, slot, err)
		}
	}
	for slot := 1; slot < awg.SlotCount; slot++ {
		connectors = append(connectors, connectorProfile{Slot: slot, ID: fmt.Sprintf("slot-%d", slot), Status: "ready"})
	}
	if _, err := allocateConnectorSlot(connectors, "new"); !errors.Is(err, ErrConflict) {
		t.Fatalf("exhausted allocation: %v", err)
	}
}

// TestBootAllowsOnlyGuardedUnavailableTunnels verifies that an unreachable peer cannot hold a healthy peer hostage or permit unguarded startup.
func TestBootAllowsOnlyGuardedUnavailableTunnels(t *testing.T) {
	e := connectorTestEngine(t)
	for _, id := range []string{"one", "two"} {
		if err := e.ApplyAWG(context.Background(), panelmodel.AWGSaveRequest{ID: id, Group: "fi", Priority: 1, Profile: connectorTestConfig}, false); err != nil {
			t.Fatal(err)
		}
	}
	probed := make(chan string, 2)
	e.readyWait = func(_ context.Context, id string) error {
		probed <- id
		if id == "two" {
			return errors.New("unreachable peer")
		}
		return nil
	}
	guards := true
	e.guardCheck = func(_ context.Context, id string, slot int) error {
		if !guards || id != "two" || slot != 1 {
			return errors.New("guards missing")
		}
		return nil
	}
	for _, allow := range []bool{true, false} {
		guards = allow
		if err := e.startAWGForBoot(context.Background()); (err == nil) != allow {
			t.Fatalf("boot guard=%v: %v", allow, err)
		}
		a, b := <-probed, <-probed
		if a == b {
			t.Fatalf("didn't start both peers: %s, %s", a, b)
		}
	}
}

// TestReadAWGProfileReturnsOnlyCommittedSecret verifies one complete editor profile and rejects reads during an interrupted publish.
func TestReadAWGProfileReturnsOnlyCommittedSecret(t *testing.T) {
	e := connectorTestEngine(t)
	request := panelmodel.AWGSaveRequest{ID: "edit", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	if err := e.ApplyAWG(context.Background(), request, false); err != nil {
		t.Fatal(err)
	}
	got, err := e.ReadAWGProfile(request.ID)
	parsed, parseErr := awg.Parse([]byte(request.Profile))
	if err != nil || parseErr != nil || got.ID != request.ID || got.Group != request.Group || got.Priority != int(request.Priority) || got.Profile != string(parsed.SecretConfig) {
		t.Fatal("incomplete editor profile")
	}
	for _, id := range []string{"unknown", "../edit"} {
		if _, err := e.ReadAWGProfile(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("expected missing profile for %q: %v", id, err)
		}
	}
	if err := os.Mkdir(filepath.Join(e.dir, pending), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := e.ReadAWGProfile(request.ID); err == nil || got.Profile != "" {
		t.Fatal("returned profile from pending generation")
	}
}

// TestAWGUnderlayGraph rejects direct and transitive cycles and deletion of an exit used by another connector.
func TestAWGUnderlayGraph(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	one := panelmodel.AWGSaveRequest{ID: "one", Group: "fi", Priority: 1, Profile: connectorTestConfig}
	two := panelmodel.AWGSaveRequest{ID: "two", Group: "ru", Priority: 1, Profile: connectorTestConfig, Underlays: []string{"one"}}
	three := panelmodel.AWGSaveRequest{ID: "three", Group: "ru", Priority: 1, Profile: connectorTestConfig, Underlays: []string{"two", "one"}}
	for _, r := range []panelmodel.AWGSaveRequest{one, two, three} {
		if err := e.ApplyAWG(ctx, r, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, values := range [][]string{{"one"}, {"three"}, {"two", "two"}, {"missing"}} {
		one.Underlays = values
		if err := e.ApplyAWG(ctx, one, true); !errors.Is(err, ErrInvalidConnector) {
			t.Fatalf("invalid selection %v: %v", values, err)
		}
	}
	if err := e.DeleteAWG(ctx, "two"); !errors.Is(err, ErrConflict) {
		t.Fatalf("removed dependency: %v", err)
	}
	read, err := e.ReadAWGProfile("three")
	if err != nil || !slices.Equal(read.Underlays, three.Underlays) {
		t.Fatalf("underlay order not retained: %v", err)
	}
	three.Underlays = nil
	if err := e.ApplyAWG(ctx, three, true); err != nil {
		t.Fatal(err)
	}
	read, err = e.ReadAWGProfile("three")
	if err != nil || !slices.Equal(read.Underlays, []string{"two", "one"}) {
		t.Fatal("legacy client cleared preferences")
	}
	three.Underlays = []string{}
	if err := e.ApplyAWG(ctx, three, true); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteAWG(ctx, "two"); err != nil {
		t.Fatalf("cleared dependency still blocked deletion: %v", err)
	}
}

// TestManualAWGStartsBackendBehindGuards proves creation can handshake through the new backend and boot releases its ordering barrier.
func TestManualAWGStartsBackendBehindGuards(t *testing.T) {
	e := connectorTestEngine(t)
	ctx := context.Background()
	if err := e.ApplyAWG(ctx, panelmodel.AWGSaveRequest{ID: "parent", Group: "fi", Priority: 1, Profile: connectorTestConfig}, false); err != nil {
		t.Fatal(err)
	}
	run := e.run
	var events []string
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == systemctl && args[0] == "start" && len(args) == 2 && args[1] == router {
			events = append(events, "backend")
		}
		return run(ctx, name, args...)
	}
	e.guardCheck = func(_ context.Context, id string, slot int) error {
		if id != "child" || slot != 1 {
			t.Fatal("incorrect guard identity")
		}
		events = append(events, "guards")
		return nil
	}
	e.readyWait = func(_ context.Context, id string) error {
		if id == "child" {
			events = append(events, "handshake")
			if !slices.Contains(events, "backend") {
				return errors.New("peer requires backend")
			}
		}
		return nil
	}
	if err := e.ApplyAWG(ctx, panelmodel.AWGSaveRequest{ID: "child", Group: "ru", Priority: 1, Profile: connectorTestConfig, Underlays: []string{"parent"}}, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"guards", "backend", "handshake"}) {
		t.Fatalf("unsafe activation: %v", events)
	}
	events = nil
	if err := e.startAWGForBoot(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(events, []string{"guards"}) {
		t.Fatalf("boot waited for the blocked backend: %v", events)
	}
}

// TestDirectConnectionNames verifies legacy reads, type-checked persistent renames and refusal to follow substituted name files.
func TestDirectConnectionNames(t *testing.T) {
	e := connectorTestEngine(t)
	source := []byte(`{"version":1,"interfaces":[{"id":"wan","type":"direct"},{"id":"vpn","type":"wireguard"}],"groups":[],"lists":[],"healthy":{}}`)
	path := filepath.Join(e.dir, "profile.json")
	if err := os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	catalog, err := e.UnderlayCandidates()
	if err != nil || len(catalog) != 2 || catalog[0].Name != "" {
		t.Fatalf("legacy catalog: %v %v", catalog, err)
	}
	lock, err := e.acquire(false)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RenameDirectConnection("wan", "Модем"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	lock.Close()
	if err := e.RenameDirectConnection("vpn", "Модем"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := e.RenameDirectConnection("missing", "Модем"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := e.RenameDirectConnection("wan", " invalid"); !errors.Is(err, ErrInvalidOrder) {
		t.Fatal(err)
	}
	for _, name := range []string{"Модем", "Кабель"} {
		if err := e.RenameDirectConnection("wan", name); err != nil {
			t.Fatal(err)
		}
		items, err := e.UnderlayCandidates()
		if err != nil || len(items) != 2 || items[0].Name != name || items[1].Name != "" {
			t.Fatalf("catalog: %v %v", items, err)
		}
	}
	if string(mustReadTestFile(t, path)) != string(source) {
		t.Fatal("routing profile changed")
	}
	names := filepath.Join(e.dir, directNamesFile)
	if err := os.Remove(names); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, names); err != nil {
		t.Fatal(err)
	}
	if err := e.RenameDirectConnection("wan", "Модем"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
