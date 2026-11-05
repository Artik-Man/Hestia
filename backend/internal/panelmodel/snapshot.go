// Package panelmodel defines the public response types of the read-only panel API.
package panelmodel

// Exit describes one configured exit and its availability in the current snapshot.
type Exit struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
}

// Group lists exits in descending priority and identifies the routing default.
type Group struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	IsDefault bool   `json:"isDefault"`
	Exits     []Exit `json:"exits" nullable:"false"`
}

// RuleList contains the saved masks and binding, including lists without a group.
type RuleList struct {
	Name    string   `json:"name,omitempty"`
	ID      string   `json:"id"`
	Group   string   `json:"group" doc:"Пустая строка означает отсутствие привязки"`
	Enabled bool     `json:"enabled"`
	Masks   []string `json:"masks" nullable:"false"`
}

// Snapshot contains the ordered groups and all domain lists returned by the panel.
type Snapshot struct {
	Groups []Group    `json:"groups" nullable:"false"`
	Lists  []RuleList `json:"lists" nullable:"false"`
}
