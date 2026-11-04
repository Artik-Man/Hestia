package panelmodel

// BindingChange sets the group of an existing list if its current group matches ExpectedGroup.
// An empty group represents an unassigned list.
type BindingChange struct {
	ListID        string `json:"listId" minLength:"1"`
	ExpectedGroup string `json:"expectedGroup"`
	Group         string `json:"group"`
}

// AppliedBinding identifies the list and group confirmed by the installed controller.
type AppliedBinding struct {
	ListID string `json:"listId"`
	Group  string `json:"group"`
}
