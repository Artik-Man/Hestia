package panelmodel

// ExitGroupChange moves an exit only if it still belongs to ExpectedGroup.
type ExitGroupChange struct {
	ExpectedGroup string `json:"expectedGroup" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Group         string `json:"group" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Priority      int    `json:"priority" minimum:"1"`
}

// ExitGroupAssignment identifies a committed exit and its confirmed position in the destination group.
type ExitGroupAssignment struct {
	ID       string `json:"id"`
	Group    string `json:"group"`
	Priority int    `json:"priority" minimum:"1"`
}

// ExitMoveCommand supplies the fixed privileged helper with an exit, both group IDs and the requested one-based position.
type ExitMoveCommand struct {
	ID string `json:"id"`
	ExitGroupChange
}
