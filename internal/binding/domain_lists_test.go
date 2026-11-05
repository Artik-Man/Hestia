package binding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// TestDomainListTransaction exercises the production profile compiler and journal with simulated gateway services.
func TestDomainListTransaction(t *testing.T) {
	e := testEngine(t)
	ctx := context.Background()
	// The named legacy rule has no display name; "deny" is a legal list ID.
	const groups = `[{"id":"fi","exits":[]},{"id":"ru","exits":[]}]`
	const lists = `[{"id":"deny","group":"","masks":["*.old.example"]}]`
	for name, data := range map[string]string{
		"profile.json":  `{"version":1,"socks_port":1080,"interfaces":[],"groups":` + groups + `,"lists":` + lists + `,"healthy":{}}`,
		"snapshot.json": `{"groups":` + groups + `,"lists":` + lists + `,"healthy":{}}`,
		"sing-box.json": `{"outbounds":[],"route":{"final":"fi"}}`,
	} {
		if err := os.WriteFile(filepath.Join(e.dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeTestDigests(t, e.dir)
	// List writes must not take down an already running VPN, even on rollback.
	e.unitCheck = func() (bool, error) { return true, nil }
	rejectNext := false
	e.run = func(ctx context.Context, name string, args ...string) error {
		if name == systemctl && strings.Contains(strings.Join(args, " "), "hestia-awg") {
			t.Fatalf("list write touched VPN service: %v", args)
		}
		if name == python {
			args[1] = filepath.Join("..", "..", "deploy", "profile.py")
			cmd := exec.CommandContext(ctx, "python3", args...)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Logf("profile compiler: %s", output)
			}
			return err
		}
		if rejectNext && name == systemctl && slices.Contains(args, smokeFresh) {
			rejectNext = false
			return errors.New("simulated live verification failure")
		}
		return nil
	}
	values := panelmodel.DomainListValues{Name: "Мой список", Group: "fi", Masks: []string{"*.Example.ORG."}}
	confirmed, err := e.CreateDomainList(ctx, values)
	if err != nil || confirmed.ID == "" || !confirmed.Enabled || confirmed.Group != "fi" {
		t.Fatalf("create: %+v, %v", confirmed, err)
	}
	var backend struct {
		Route struct {
			Rules []struct {
				Suffix   string `json:"domain_suffix"`
				Outbound string `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json")), &backend); err != nil || len(backend.Route.Rules) != 1 || backend.Route.Rules[0].Suffix != "example.org" || backend.Route.Rules[0].Outbound != "fi" {
		t.Fatalf("compiled routes: %+v, %v", backend.Route.Rules, err)
	}
	if _, err := e.CreateDomainList(ctx, values); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate POST: %v", err)
	}
	prior := panelmodel.RuleList{ID: "deny", Masks: []string{"*.old.example"}}
	change := panelmodel.DomainListUpdate{Expected: prior, List: panelmodel.DomainListValues{Name: "Переименован", Group: "", Masks: []string{}}}
	renamed, err := e.UpdateDomainList(ctx, "deny", change)
	if err != nil || renamed.ID != "deny" || renamed.Enabled || renamed.Name != change.List.Name {
		t.Fatalf("legacy edit: %+v, %v", renamed, err)
	}
	if _, err := e.UpdateDomainList(ctx, "deny", change); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	change.Expected = renamed
	change.List.Group = "unknown"
	if _, err := e.UpdateDomainList(ctx, "deny", change); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown group: %v", err)
	}
	change.List.Group = ""
	change.List.Name = confirmed.Name
	if _, err := e.UpdateDomainList(ctx, "deny", change); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name update: %v", err)
	}
	priorFiles := make(map[string][]byte)
	for _, name := range managedFiles {
		priorFiles[name] = mustReadTestFile(t, filepath.Join(e.dir, name))
	}
	change.List.Name = "Проверка отката"
	rejectNext = true
	if _, err := e.UpdateDomainList(ctx, "deny", change); err == nil || rejectNext {
		t.Fatalf("unconfirmed edit: %v", err)
	}
	for name, data := range priorFiles {
		if !bytes.Equal(mustReadTestFile(t, filepath.Join(e.dir, name)), data) {
			t.Fatalf("rollback changed %s", name)
		}
	}
	if err := e.DeleteDomainList(ctx, prior); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete ignored stale list: %v", err)
	}
	rejectNext = true
	if err := e.DeleteDomainList(ctx, confirmed); err == nil || rejectNext {
		t.Fatalf("unconfirmed deletion: %v", err)
	}
	for name, data := range priorFiles {
		if !bytes.Equal(mustReadTestFile(t, filepath.Join(e.dir, name)), data) {
			t.Fatalf("delete rollback changed %s", name)
		}
	}
	if err := e.DeleteDomainList(ctx, confirmed); err != nil {
		t.Fatal(err)
	}
	// The active rule must be removed from the actual installed backend as well as the snapshot.
	var after struct {
		Route struct{ Rules []json.RawMessage }
	}
	if err := json.Unmarshal(mustReadTestFile(t, filepath.Join(e.dir, "sing-box.json")), &after); err != nil || len(after.Route.Rules) != 0 {
		t.Fatalf("deleted rule still active: %+v, %v", after, err)
	}
	if err := e.DeleteDomainList(ctx, confirmed); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat deletion: %v", err)
	}
	if err := e.DeleteDomainList(ctx, renamed); err != nil {
		t.Fatalf("delete last list: %v", err)
	}
}

// TestValidateDomainListValues rejects invalid masks even for unassigned lists and distinguishes [] from null.
func TestValidateDomainListValues(t *testing.T) {
	for _, values := range []panelmodel.DomainListValues{
		{Name: "ok", Masks: nil}, {Name: "ok", Masks: []string{"example.org"}}, {Name: "ok", Masks: []string{"*.a..b"}},
		{Name: "ok", Group: "../fi", Masks: []string{}}, {Name: " bad", Masks: []string{}},
	} {
		if !errors.Is(ValidateDomainListValues(values), ErrInvalidDomainList) {
			t.Fatalf("invalid value accepted: %+v", values)
		}
	}
}
