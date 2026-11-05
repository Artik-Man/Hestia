package panelmodel

import (
	"bytes"
	"encoding/json"
	"errors"
)

// UnderlayIDs preserves transport preference order. Omission means unchanged on update and an empty array requests automatic routing.
type UnderlayIDs []string

// UnmarshalJSON rejects explicit null and malformed selections while retaining the distinction between an absent and empty list.
func (ids *UnderlayIDs) UnmarshalJSON(data []byte) error {
	var parsed []string
	if bytes.Equal(data, []byte("null")) || json.Unmarshal(data, &parsed) != nil || parsed == nil {
		return errors.New("underlays must be an ordered array of exit IDs")
	}
	*ids = parsed
	return nil
}

// AWGConnection contains public AmneziaWG metadata and never includes profile or key material.
type AWGConnection struct {
	Name           string      `json:"name" minLength:"1" maxLength:"80"`
	Underlays      UnderlayIDs `json:"underlays,omitzero" maxItems:"64" nullable:"false"`
	ActiveUnderlay string      `json:"activeUnderlay,omitempty"`
	ID             string      `json:"id" minLength:"1"`
	Group          string      `json:"group" minLength:"1"`
	Priority       int         `json:"priority" minimum:"1"`
	Status         string      `json:"status" enum:"configured,checking,ready,error"`
	IPv6Blocked    bool        `json:"ipv6Blocked"`
}

// AWGCheckRequest submits an untrusted candidate profile for a temporary runtime check.
type AWGCheckRequest struct {
	Profile string `json:"profile" minLength:"1"`
}

// AWGCheckResult describes a runtime check without echoing profile input or secrets.
type AWGCheckResult struct {
	Status     string `json:"status" enum:"handshake_confirmed"`
	Message    string `json:"message"`
	RouteReady bool   `json:"routeReady"`
}

// AWGCreateRequest carries the visible name and settings for a new connection; the server assigns its ID.
type AWGCreateRequest struct {
	Name      string      `json:"name" minLength:"1" maxLength:"80"`
	Underlays UnderlayIDs `json:"underlays,omitzero" maxItems:"64" nullable:"false" doc:"Идентификаторы выходов в порядке предпочтения; пустой список — обычный маршрут"`
	Group     string      `json:"group" minLength:"1"`
	Priority  AWGPriority `json:"priority,omitempty" minimum:"1"`
	Profile   string      `json:"profile" minLength:"1"`
}

// AWGSaveRequest stores one validated profile and its selected group position.
type AWGSaveRequest struct {
	Name      string      `json:"name" minLength:"1" maxLength:"80"`
	Underlays UnderlayIDs `json:"underlays,omitzero" maxItems:"64" nullable:"false" doc:"Идентификаторы выходов в порядке предпочтения; пустой список — обычный маршрут"`
	ID        string      `json:"id" minLength:"1"`
	Group     string      `json:"group" minLength:"1"`
	Priority  AWGPriority `json:"priority,omitempty" minimum:"1"`
	Profile   string      `json:"profile" minLength:"1"`
}

// AWGUpdateRequest replaces mutable settings while the path keeps the connection ID stable.
type AWGUpdateRequest struct {
	Name      AWGUpdateName  `json:"name,omitempty" minLength:"1" maxLength:"80"`
	Underlays UnderlayIDs    `json:"underlays,omitzero" maxItems:"64" nullable:"false" doc:"Идентификаторы выходов в порядке предпочтения; пустой список — обычный маршрут"`
	Group     AWGUpdateGroup `json:"group,omitempty" minLength:"1"`
	Priority  AWGPriority    `json:"priority,omitempty" minimum:"1"`
	Profile   string         `json:"profile" minLength:"1"`
}

// AWGIDRequest identifies one connection for a privileged read or delete operation.
type AWGIDRequest struct {
	ID string `json:"id" minLength:"1"`
}

// AWGConnectionProfile contains the complete normalized secret configuration for editing one connection.
type AWGConnectionProfile struct {
	Name      string      `json:"name" minLength:"1" maxLength:"80"`
	Underlays UnderlayIDs `json:"underlays,omitzero" maxItems:"64" nullable:"false" doc:"Идентификаторы выходов в порядке предпочтения; пустой список — обычный маршрут"`
	ID        string      `json:"id" minLength:"1"`
	Group     string      `json:"group" minLength:"1"`
	Priority  int         `json:"priority" minimum:"1"`
	Profile   string      `json:"profile" minLength:"1"`
}

// AWGUnderlayCandidate identifies an existing exit eligible to carry a WireGuard connection.
type AWGUnderlayCandidate struct {
	Name string `json:"name,omitempty" maxLength:"80"`
	ID   string `json:"id" minLength:"1"`
	Type string `json:"type" enum:"direct,wireguard,amneziawg,hysteria2"`
}

// AWGPriority uses zero internally for an omitted position and rejects explicit nonpositive positions.
type AWGPriority int

// UnmarshalJSON accepts only positive integer priorities.
func (p *AWGPriority) UnmarshalJSON(data []byte) error {
	var n int
	if json.Unmarshal(data, &n) != nil || n < 1 {
		return errors.New("priority must be a positive integer")
	}
	*p = AWGPriority(n)
	return nil
}

// AWGUpdateGroup distinguishes omitted placement from an explicitly invalid empty or null group.
type AWGUpdateGroup string

// UnmarshalJSON accepts a nonempty group identifier for subsequent identifier validation.
func (g *AWGUpdateGroup) UnmarshalJSON(data []byte) error {
	var id string
	if json.Unmarshal(data, &id) != nil || id == "" {
		return errors.New("group must be a nonempty identifier")
	}
	*g = AWGUpdateGroup(id)
	return nil
}

// AWGUpdateName distinguishes omitted names from invalid explicit empty or null names.
type AWGUpdateName string

// UnmarshalJSON accepts a nonempty name for subsequent display-name validation.
func (n *AWGUpdateName) UnmarshalJSON(data []byte) error {
	var value string
	if json.Unmarshal(data, &value) != nil || value == "" {
		return errors.New("name must be a nonempty string")
	}
	*n = AWGUpdateName(value)
	return nil
}
