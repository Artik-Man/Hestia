package binding

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
		if name == systemctl && len(args) >= 2 && args[0] == "start" && args[1] == awgUnit && !serviceFailed {
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
	e.readyWait = func(context.Context) error {
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
	e.readyWait = func(context.Context) error { return nil }
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
