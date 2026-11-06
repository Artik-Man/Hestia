package binding

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// ErrInvalidDomainList indicates malformed editable fields or an invalid list identifier.
var ErrInvalidDomainList = errors.New("invalid domain list")

// ValidateDomainListValues requires a display name, an optional routing group ID and a bounded array of wildcard DNS masks.
func ValidateDomainListValues(values panelmodel.DomainListValues) error {
	if ValidateGroupName(values.Name) != nil || (values.Group != "" && ValidateGroupID(values.Group) != nil) ||
		values.Masks == nil || len(values.Masks) > 1024 {
		return ErrInvalidDomainList
	}
	for _, mask := range values.Masks {
		if !routing.ValidMask(mask) {
			return ErrInvalidDomainList
		}
	}
	return nil
}

// CreateDomainList allocates a stable routing ID and returns the new list once the gateway confirms the transaction.
func (e Engine) CreateDomainList(ctx context.Context, values panelmodel.DomainListValues) (panelmodel.RuleList, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return panelmodel.RuleList{}, err
	}
	return e.saveDomainList(ctx, "l-"+hex.EncodeToString(random[:]), nil, values)
}

// UpdateDomainList replaces one list if its current fields still match the original snapshot read by the client.
func (e Engine) UpdateDomainList(ctx context.Context, id string, update panelmodel.DomainListUpdate) (panelmodel.RuleList, error) {
	if !awgID(id) || update.Expected.ID != id || update.Expected.Masks == nil {
		return panelmodel.RuleList{}, ErrInvalidDomainList
	}
	return e.saveDomainList(ctx, id, &update.Expected, update.List)
}

// saveDomainList compares under the installation lock, stages profile and routing changes together and verifies the full resulting snapshot.
func (e Engine) saveDomainList(ctx context.Context, id string, previous *panelmodel.RuleList, values panelmodel.DomainListValues) (panelmodel.RuleList, error) {
	if err := ValidateDomainListValues(values); err != nil {
		return panelmodel.RuleList{}, err
	}
	result := panelmodel.RuleList{ID: id, Name: values.Name, Group: values.Group, Masks: values.Masks, Enabled: values.Group != ""}
	item := routing.List{ID: id, Name: values.Name, Group: values.Group, Masks: values.Masks}
	mutate := func(cfg *controller.Config) error {
		if values.Group != "" && !slices.ContainsFunc(cfg.Groups, func(g routing.Group) bool { return g.ID == values.Group }) {
			return ErrNotFound
		}
		index := -1
		for i, current := range cfg.Lists {
			if current.ID == id {
				index = i
				if previous == nil || !matchesDomainList(current, *previous) {
					return ErrConflict
				}
			} else if effectiveGroupName(current.ID, current.Name) == values.Name {
				return ErrConflict
			}
		}
		if previous == nil {
			cfg.Lists = append(cfg.Lists, item)
		} else if index >= 0 {
			cfg.Lists[index] = item
		} else {
			return ErrNotFound
		}
		return nil
	}
	prepare := func(stage string) error {
		data, err := json.Marshal(values)
		if err != nil {
			return err
		}
		request := filepath.Join(stage, "list-values.json")
		if err := os.WriteFile(request, data, 0600); err != nil {
			return err
		}
		if err := e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.SaveList, Source: e.dir, Stage: stage, ID: id}); err != nil {
			return err
		}
		return os.Remove(request)
	}
	if err := e.applyDomainList(ctx, mutate, prepare, previous != nil && reflect.DeepEqual(*previous, result)); err != nil {
		return panelmodel.RuleList{}, err
	}
	return result, nil
}

// matchesDomainList compares all observed list fields, including the derived binding status and ordered masks.
func matchesDomainList(current routing.List, expected panelmodel.RuleList) bool {
	return current.ID == expected.ID && current.Name == expected.Name && current.Group == expected.Group &&
		(current.Group != "") == expected.Enabled && slices.Equal(current.Masks, expected.Masks)
}

// DeleteDomainList removes the selected list and its routes only if the operator's snapshot is still current.
func (e Engine) DeleteDomainList(ctx context.Context, expected panelmodel.RuleList) error {
	if !awgID(expected.ID) || expected.Masks == nil {
		return ErrInvalidDomainList
	}
	mutate := func(cfg *controller.Config) error {
		for i, current := range cfg.Lists {
			if current.ID != expected.ID {
				continue
			}
			if !matchesDomainList(current, expected) {
				return ErrConflict
			}
			cfg.Lists = slices.Delete(cfg.Lists, i, i+1)
			return nil
		}
		return ErrNotFound
	}
	prepare := func(stage string) error {
		return e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.DeleteList, Source: e.dir, Stage: stage, ID: expected.ID})
	}
	return e.applyDomainList(ctx, mutate, prepare, false)
}

// applyDomainList calculates the expected snapshot under the write lock, verifies the entire staged generation,
// and marks both application and recovery to preserve the active connector.
func (e Engine) applyDomainList(ctx context.Context, mutate func(*controller.Config) error, prepare func(string) error, noChange bool) error {
	var expected controller.Config
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
		expected = cfg
		return mutate(&expected)
	}
	stageList := func(stage string) error {
		if err := prepare(stage); err != nil {
			return err
		}
		return writeDurably(filepath.Join(stage, routingOnlyMarker), []byte("1\n"))
	}
	return e.apply(ctx, stageList, check, noChange)
}
