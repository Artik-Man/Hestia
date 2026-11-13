package binding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestHysteria2Lifecycle exercises committed private/public data, group moves, password retention and rollback using the real compiler.
func TestHysteria2Lifecycle(t *testing.T) {
	e := managedConnectorTestEngine(t)
	ctx := context.Background()
	const id = "943dcd5f-96ab-4a3b-841b-55d8bcafdc62"
	req := panelmodel.Hysteria2WriteRequest{Hysteria2Settings: panelmodel.Hysteria2Settings{Name: "Тест", Underlay: "keenetic-direct", Server: "vpn.example.test", Port: 443}, Group: "default", Password: "test-only-secret"}
	created, err := e.SaveHysteria2(ctx, id, req, false)
	if err != nil || created.Priority != 2 {
		t.Fatalf("create: %v", err)
	}
	detail, err := e.ReadHysteria2Profile(id)
	if err != nil || detail.Password != req.Password || !slices.Equal(detail.Underlays, []string{"keenetic-direct"}) {
		t.Fatal("missing private detail or legacy physical transport")
	}
	candidates, err := e.UnderlayCandidates()
	if err != nil || !slices.Contains(candidates, panelmodel.AWGUnderlayCandidate{Name: req.Name, ID: id, Type: "hysteria2", Enabled: true}) {
		t.Fatal("missing transport candidate")
	}
	if err := e.CreateGroup(ctx, "reserve"); err != nil {
		t.Fatal(err)
	}
	if err := e.MoveExit(ctx, id, "default", "reserve", 1); err != nil {
		t.Fatal(err)
	}
	listed, err := e.ListHysteria2()
	if err != nil || len(listed) != 1 || listed[0].Group != "reserve" || listed[0].Priority != 1 {
		t.Fatalf("list after move: %v", err)
	}
	encoded, err := json.Marshal(listed)
	if err != nil || bytes.Contains(encoded, []byte(req.Password)) || bytes.Contains(mustReadTestFile(t, filepath.Join(e.dir, "snapshot.json")), []byte(req.Password)) {
		t.Fatal("secret escaped into public data")
	}
	prior, err := readStoredProfile(e.dir)
	if err != nil || len(prior.Hysteria2[0].ProbeSecret) != 64 || bytes.Contains(encoded, []byte(prior.Hysteria2[0].ProbeSecret)) {
		t.Fatal("missing or exposed local probe credential")
	}
	req.Group, req.Password, req.Name = "", "", "Переименовано"
	if _, err := e.SaveHysteria2(ctx, id, req, true); err != nil {
		t.Fatal(err)
	}
	current, err := readStoredProfile(e.dir)
	if err != nil || current.Hysteria2[0].Password != "test-only-secret" || current.Hysteria2[0].Name != req.Name || current.Hysteria2[0].ProbeSecret != prior.Hysteria2[0].ProbeSecret {
		t.Fatal("rename lost saved settings")
	}
	changedPeer := req
	changedPeer.Server = "replacement.example.test"
	if _, err := e.SaveHysteria2(ctx, id, changedPeer, true); !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("saved password could be redirected to a different endpoint: %v", err)
	}
	previous := mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json"))
	baseRun := e.run
	failed := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if !failed && name == systemctl && len(args) == 2 && args[1] == smokeFresh {
			failed = true
			return errors.New("candidate failed")
		}
		return baseRun(ctx, name, args...)
	}
	req.Password = "replacement"
	if _, err := e.SaveHysteria2(ctx, id, req, true); err == nil || !failed {
		t.Fatal("activation failure accepted")
	}
	if !bytes.Equal(previous, mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json"))) {
		t.Fatal("prior backend not restored")
	}
	if err := e.DeleteHysteria2(ctx, id); err != nil {
		t.Fatal(err)
	}
	listed, err = e.ListHysteria2()
	if err != nil || len(listed) != 0 {
		t.Fatal("deleted profile still visible", err)
	}
}

// TestHysteria2CrossProtocolDependencies checks backup edges, legacy physical references, missing references and mixed cycles.
func TestHysteria2CrossProtocolDependencies(t *testing.T) {
	p := storedProfile{}
	p.Connectors = []connectorProfile{{ID: "wireguard-exit", Underlays: []string{"hysteria-exit"}}, {ID: "backup-exit"}}
	p.Hysteria2 = []storedHysteria2{{ID: "hysteria-exit", Hysteria2Settings: panelmodel.Hysteria2Settings{Underlay: "backup-exit"}}}
	if !validUnderlayGraph(p) || !usesUnderlay(p, "hysteria-exit") || !usesUnderlay(p, "backup-exit") {
		t.Fatal("missing legacy or cross-protocol dependency")
	}
	for _, choices := range [][]string{{"backup-exit", "wireguard-exit"}, {"missing-exit"}, {"hysteria-exit"}, {"backup-exit", "backup-exit"}} {
		p.Hysteria2[0].Underlay = ""
		p.Hysteria2[0].Underlays = choices
		if validUnderlayGraph(p) {
			t.Fatalf("invalid dependencies accepted: %v", choices)
		}
	}
}

// TestHysteria2MixedTransportTransaction protects referenced exits and validates ordered priorities and cycle rejection through real writes.
func TestHysteria2MixedTransportTransaction(t *testing.T) {
	e := managedConnectorTestEngine(t)
	ctx := context.Background()
	const relayID = "943dcd5f-96ab-4a3b-841b-55d8bcafdc62"
	wg := panelmodel.AWGSaveRequest{Name: "Первый", ID: "test-wg", Group: "default", Profile: connectorTestConfig}
	if err := e.ApplyAWG(ctx, wg, false); err != nil {
		t.Fatal(err)
	}
	req := panelmodel.Hysteria2WriteRequest{Hysteria2Settings: panelmodel.Hysteria2Settings{Name: "Выход", Server: "vpn.example.test", Port: 443, Underlays: []string{wg.ID, "keenetic-direct"}}, Group: "default", Password: "example-test"}
	created, err := e.SaveHysteria2(ctx, relayID, req, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(created.Underlays, req.Underlays) {
		t.Fatalf("lost transport order: %v", created.Underlays)
	}
	if err := e.DeleteAWG(ctx, wg.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted referenced WG: %v", err)
	}
	wg.Underlays = []string{relayID}
	if err := e.ApplyAWG(ctx, wg, true); !errors.Is(err, ErrInvalidConnector) {
		t.Fatalf("accepted cycle: %v", err)
	}
	req.Underlays = panelmodel.UnderlayIDs{}
	req.Group = ""
	if _, err := e.SaveHysteria2(ctx, relayID, req, true); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyAWG(ctx, wg, true); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteHysteria2(ctx, relayID); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleted referenced Hysteria: %v", err)
	}
	final, err := e.ReadHysteria2Profile(relayID)
	if err != nil || final.Priority != created.Priority || len(final.Underlays) != 0 {
		t.Fatalf("changed group priority or automatic transport: %v", err)
	}
}
