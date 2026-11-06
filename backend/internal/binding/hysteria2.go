package binding

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"slices"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// storedHysteria2 is kept only in private, journaled source generations. Groups own the exit order.
type storedHysteria2 struct {
	panelmodel.Hysteria2Settings
	ID          string `json:"id"`
	Password    string `json:"password"`
	ProbeSecret string `json:"probeSecret"`
}

// publicConnection projects the editable settings and current group placement without the credential.
func (h storedHysteria2) publicConnection(groups []connectorGroup) panelmodel.Hysteria2Connection {
	group, priority := groupExitLocation(groups, h.ID)
	h.Underlays = h.EffectiveUnderlays()
	h.Underlay = ""
	return panelmodel.Hysteria2Connection{Hysteria2Settings: h.Hysteria2Settings, ID: h.ID, Group: group, Priority: priority}
}

// ListHysteria2 reads the public fields of the committed generation under the installer's shared lock.
func (e Engine) ListHysteria2() ([]panelmodel.Hysteria2Connection, error) {
	lock, err := e.acquire(false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	current, err := e.physicalProfile()
	if err != nil {
		return nil, err
	}
	result := make([]panelmodel.Hysteria2Connection, 0, len(current.Hysteria2))
	for _, item := range current.Hysteria2 {
		result = append(result, item.publicConnection(current.Groups))
	}
	return result, nil
}

// ReadHysteria2Profile reads the password of exactly one saved connection while holding the installation lock.
func (e Engine) ReadHysteria2Profile(id string) (panelmodel.Hysteria2ConnectionProfile, error) {
	var result panelmodel.Hysteria2ConnectionProfile
	lock, err := e.acquire(false)
	if err != nil {
		return result, err
	}
	defer lock.Close()
	current, err := e.physicalProfile()
	if err != nil {
		return result, err
	}
	for _, item := range current.Hysteria2 {
		if item.ID == id {
			result.Hysteria2Connection = item.publicConnection(current.Groups)
			result.Password = item.Password
			return result, nil
		}
	}
	return result, ErrNotFound
}

// SaveHysteria2 stages a profile and retains placement on edit. Reusing a stored password requires the same peer and TLS policy.
// Success requires verification of the running candidate generation.
func (e Engine) SaveHysteria2(ctx context.Context, id string, req panelmodel.Hysteria2WriteRequest, update bool) (panelmodel.Hysteria2Connection, error) {
	var result panelmodel.Hysteria2Connection
	if !awg.ValidConnectionID(id) || panelmodel.ValidateHysteria2(req, update) != nil {
		return result, ErrInvalidConnector
	}
	check := func(data []byte, staged bool) error {
		return checkConnectorSnapshot(data, id, req.Group, update, staged)
	}
	prepare := func(stage string) error {
		current, err := e.hysteriaSource(ctx)
		if err != nil {
			return err
		}
		item := storedHysteria2{Hysteria2Settings: req.Hysteria2Settings, ID: id, Password: req.Password}
		if req.Underlay != "" {
			item.Underlays = req.EffectiveUnderlays()
			item.Underlay = ""
		}
		index := slices.IndexFunc(current.Hysteria2, func(h storedHysteria2) bool { return h.ID == id })
		if update {
			if index < 0 {
				return ErrNotFound
			}
			saved := current.Hysteria2[index]
			if req.Underlay == "" && req.Underlays == nil {
				item.Underlays = saved.EffectiveUnderlays()
			}
			if item.Password == "" {
				if saved.Server != req.Server || saved.Port != req.Port || saved.ServerName != req.ServerName || saved.CertificatePEM != req.CertificatePEM {
					return ErrInvalidConnector
				}
				item.Password = saved.Password
			}
			item.ProbeSecret = current.Hysteria2[index].ProbeSecret
			current.Hysteria2[index] = item
		} else {
			if index >= 0 || idInProfile(current, id) || connectorIndex(current.Connectors, id) >= 0 {
				return ErrConflict
			}
			if len(current.Hysteria2) >= 64 {
				return ErrConflict
			}
			groupIndex := connectorGroupIndex(current.Groups, req.Group)
			if groupIndex < 0 {
				return ErrNotFound
			}
			group := &current.Groups[groupIndex]
			group.Exits = append(group.Exits, id)
			if current.Inbounds != nil && len(group.Exits) == 1 {
				group.DefaultExit = id
			}
			current.Healthy[id] = true
			var random [32]byte
			if _, err := rand.Read(random[:]); err != nil {
				return ErrUnavailable
			}
			item.ProbeSecret = hex.EncodeToString(random[:])
			current.Hysteria2 = append(current.Hysteria2, item)
		}
		if !validUnderlayGraph(current) {
			return ErrInvalidConnector
		}
		result = item.publicConnection(current.Groups)
		return compileConnectorGeneration(ctx, e, stage, current)
	}
	if err := e.apply(ctx, prepare, check, false); err != nil {
		return panelmodel.Hysteria2Connection{}, err
	}
	return result, nil
}

// hysteriaSource checks the source against the installed runtime before promoting old profiles to version two.
func (e Engine) hysteriaSource(ctx context.Context) (storedProfile, error) {
	if err := e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.Validate, Source: e.dir}); err != nil {
		return storedProfile{}, ErrUnavailable
	}
	p, err := readStoredProfile(e.dir)
	if err != nil || p.Healthy == nil {
		return storedProfile{}, ErrUnavailable
	}
	if p.Version == 1 {
		p.Version = 2
		p.Connectors = []connectorProfile{}
	}
	return p, nil
}

// DeleteHysteria2 removes one private profile and repairs neighboring exit priorities in the same transaction.
func (e Engine) DeleteHysteria2(ctx context.Context, id string) error {
	if !awg.ValidConnectionID(id) {
		return ErrNotFound
	}
	check := func(data []byte, staged bool) error {
		if staged {
			return checkConnectorSnapshot(data, id, "", false, false)
		}
		return checkConnectorSnapshot(data, id, "", true, false)
	}
	prepare := func(stage string) error {
		current, err := e.hysteriaSource(ctx)
		if err != nil {
			return err
		}
		idx := slices.IndexFunc(current.Hysteria2, func(h storedHysteria2) bool { return h.ID == id })
		if idx < 0 {
			return ErrNotFound
		}
		if usesUnderlay(current, id) {
			return ErrConflict
		}
		current.Hysteria2 = slices.Delete(current.Hysteria2, idx, idx+1)
		group, _ := groupExitLocation(current.Groups, id)
		if err := removeGroupExit(current.Groups, group, id); err != nil {
			return err
		}
		delete(current.Healthy, id)
		for i := range current.Connectors {
			c := &current.Connectors[i]
			c.Group, c.Priority = groupExitLocation(current.Groups, c.ID)
			if err := updateStagedMetadata(stage, *c); err != nil {
				return err
			}
		}
		return compileConnectorGeneration(ctx, e, stage, current)
	}
	return e.apply(ctx, prepare, check, false)
}
