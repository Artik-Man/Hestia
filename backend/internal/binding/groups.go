package binding

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/profileexec"
	"reflect"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/routing"
)

// ValidateGroupID requires a lowercase routing identifier that can be used as a group selector tag.
func ValidateGroupID(id string) error {
	if !awgID(id) || id == "deny" {
		return ErrInvalidOrder
	}
	return nil
}

// ValidateGroupName accepts one human-readable group name of up to 80 Unicode characters without controls or outer whitespace.
func ValidateGroupName(name string) error {
	if name == "" || !utf8.ValidString(name) || name != strings.TrimSpace(name) ||
		utf8.RuneCountInString(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return ErrInvalidOrder
	}
	return nil
}

// CreateGroup preserves the legacy operation which displays its explicitly supplied routing ID as the group name.
func (e Engine) CreateGroup(ctx context.Context, id string) error {
	return e.writeGroup(ctx, id, "", true)
}

// CreateNamedGroup creates an empty group with a stable random routing ID and returns the ID only after gateway confirmation.
func (e Engine) CreateNamedGroup(ctx context.Context, name string) (string, error) {
	if err := ValidateGroupName(name); err != nil {
		return "", err
	}
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	id := fmt.Sprintf("g-%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	if err := e.writeGroup(ctx, id, name, true); err != nil {
		return "", err
	}
	return id, nil
}

// RenameGroup updates the display name of an existing group while retaining its routing ID and bindings.
func (e Engine) RenameGroup(ctx context.Context, id, name string) error {
	if err := ValidateGroupName(name); err != nil {
		return err
	}
	return e.writeGroup(ctx, id, name, false)
}

// writeGroup stages a group creation or a name update under the installer lock and checks the full resulting snapshot.
func (e Engine) writeGroup(ctx context.Context, id, name string, create bool) error {
	if err := ValidateGroupID(id); err != nil {
		return err
	}
	var expected controller.Config
	check := func(data []byte, staged bool) error {
		current, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if staged {
			if !reflect.DeepEqual(current, expected) {
				return ErrUnavailable
			}
			return nil
		}
		index := -1
		for i, group := range current.Groups {
			if group.ID == id {
				index = i
			}
			if create && (group.ID == id || slices.Contains(group.Exits, id)) {
				return ErrConflict
			}
			if group.ID != id && effectiveGroupName(group.ID, group.Name) == effectiveGroupName(id, name) {
				return ErrConflict
			}
		}
		expected = current
		if create {
			expected.Groups = append(expected.Groups, routing.Group{ID: id, Name: name, Exits: []string{}})
		} else if index >= 0 {
			expected.Groups[index].Name = name
		} else {
			return ErrNotFound
		}
		return nil
	}
	prepare := func(stage string) error {
		mode := profileexec.RenameGroup
		if create {
			mode = profileexec.CreateGroup
		}
		return e.profileCompiler().Apply(ctx, profileexec.Request{Operation: mode, Source: e.dir, Stage: stage, ID: id, Name: name})
	}
	return e.apply(ctx, prepare, check, false)
}

// effectiveGroupName uses the routing ID as the visible name of a legacy group without an explicit label.
func effectiveGroupName(id, name string) string {
	if name == "" {
		return id
	}
	return name
}

// DeleteGroup unbinds its lists and removes an empty non-default selector under the installer lock and confirms the complete resulting snapshot.
func (e Engine) DeleteGroup(ctx context.Context, id string) error {
	if err := ValidateGroupID(id); err != nil {
		return err
	}
	var expected controller.Config
	check := func(data []byte, staged bool) error {
		current, err := controller.CheckSnapshot(data)
		if err != nil {
			return ErrUnavailable
		}
		if staged {
			if !reflect.DeepEqual(current, expected) {
				return ErrUnavailable
			}
			return nil
		}
		index := slices.IndexFunc(current.Groups, func(group routing.Group) bool { return group.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		if index == 0 || len(current.Groups[index].Exits) > 0 {
			return ErrConflict
		}
		expected = current
		if err := e.checkCountryReferences(id, current.CountryMap); err != nil {
			return err
		}
		expected.Groups = slices.Delete(current.Groups, index, index+1)
		for i := range expected.Lists {
			if expected.Lists[i].Group == id {
				expected.Lists[i].Group = ""
			}
		}
		return nil
	}
	prepare := func(stage string) error {
		return e.profileCompiler().Apply(ctx, profileexec.Request{Operation: profileexec.DeleteGroup, Source: e.dir, Stage: stage, ID: id})
	}
	return e.apply(ctx, prepare, check, false)
}
