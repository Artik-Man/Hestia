package panelmodel

import (
	"bytes"
	"encoding/json"
)

// OrderedGroup identifies one group and lists all of its exits in descending priority.
type OrderedGroup struct {
	ID    string   `json:"id" minLength:"1"`
	Exits []string `json:"exits" nullable:"false"`
}

// GroupOrderChange replaces an ordered topology only when Expected still matches the gateway.
type GroupOrderChange struct {
	Expected []OrderedGroup `json:"expected" minItems:"1" nullable:"false"`
	Groups   []OrderedGroup `json:"groups" minItems:"1" nullable:"false"`
}

// AppliedOrder contains the complete order confirmed by the running gateway.
type AppliedOrder struct {
	Groups []OrderedGroup `json:"groups" nullable:"false"`
}

// UnmarshalJSON decodes the closed order schema and rejects unknown properties on groups as well as the request.
func (c *GroupOrderChange) UnmarshalJSON(data []byte) error {
	type wireOrder GroupOrderChange
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*wireOrder)(c))
}
