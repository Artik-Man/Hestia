package binding

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"maps"
	"os"
	"path/filepath"
	"reflect"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// MigrateCountryMap imports saved assignments and upgrades legacy managed domain routes that lack a country policy.
func (e Engine) MigrateCountryMap(ctx context.Context) error {
	snapshot, err := os.ReadFile(filepath.Join(e.dir, "snapshot.json"))
	if err != nil {
		return err
	}
	cfg, err := controller.CheckSnapshot(snapshot)
	if err != nil {
		return err
	}
	if cfg.CountryMap != nil {
		return nil
	}
	policy, err := e.readCountryMap()
	if errors.Is(err, os.ErrNotExist) {
		if len(cfg.Lists) == 0 {
			return nil
		}
		if _, err := os.Stat(filepath.Join(e.dir, "profile.json")); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		// Legacy gateways with domain lists also need the client TUN sniff rule,
		// even when nobody has visited the country-map screen yet.
		_, err = e.applyCountryMap(ctx, policy, true)
		return err
	}
	if err != nil {
		return err
	}
	// A stored disabled policy still migrates so upgraded TUN domain sniffing becomes active.
	_, err = e.ApplyCountryMap(ctx, policy)
	return err
}

// ApplyCountryMap compares the version under the installation lock and commits the new policy with the routing generation.
func (e Engine) ApplyCountryMap(ctx context.Context, change panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	return e.applyCountryMap(ctx, change, false)
}

// applyCountryMap initializes an absent legacy policy only during migration and compares ordinary writes by version.
func (e Engine) applyCountryMap(ctx context.Context, change panelmodel.CountryMap, initialize bool) (panelmodel.CountryMap, error) {
	var expected controller.Config
	var result panelmodel.CountryMap
	check := func(data []byte, staged bool) error {
		cfg, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if staged {
			if !reflect.DeepEqual(cfg, expected) {
				return ErrUnavailable
			}
			return nil
		}
		policy := cfg.CountryMap
		if policy == nil {
			legacy, err := e.readCountryMap()
			if initialize && errors.Is(err, os.ErrNotExist) && len(cfg.Groups) > 0 {
				legacy.Version = rand.Text()
				legacy.Assignments = make(map[string]string, len(countryCodes))
				for _, code := range countryCodes {
					legacy.Assignments[code] = cfg.Groups[0].ID
				}
				change = legacy
				err = nil
			} else if errors.Is(err, os.ErrNotExist) {
				return ErrConflict
			}
			if err != nil {
				return err
			}
			policy = &legacy
		}
		if change.Version != policy.Version {
			return ErrConflict
		}
		if !completeCountryMap(change) {
			return ErrInvalidCountryMap
		}
		available := map[string]bool{}
		for _, group := range cfg.Groups {
			available[group.ID] = true
		}
		for _, group := range change.Assignments {
			if !available[group] {
				return ErrInvalidCountryMap
			}
		}
		result = change
		if cfg.CountryMap != nil && change.Enabled == policy.Enabled && maps.Equal(change.Assignments, policy.Assignments) {
			return errCountryMapUnchanged
		}
		result.Version = rand.Text()
		expected = cfg
		expected.CountryMap = &result
		return nil
	}
	prepare := func(stage string) error {
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		request := filepath.Join(stage, "country-request.json")
		if err = os.WriteFile(request, body, 0600); err != nil {
			return err
		}
		if err = e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.CountryMap, Source: e.dir, Stage: stage}); err != nil {
			return err
		}
		if err = os.Remove(request); err != nil {
			return err
		}
		return writeDurably(filepath.Join(stage, routingOnlyMarker), []byte("1\n"))
	}
	err := e.apply(ctx, prepare, check, false)
	if errors.Is(err, errCountryMapUnchanged) {
		err = nil
	}
	return result, err
}

var errCountryMapUnchanged = errors.New("country map already applied")
