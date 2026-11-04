package panelmodel

// AWGConnection contains public AmneziaWG metadata and never includes profile or key material.
type AWGConnection struct {
	ID          string `json:"id" minLength:"1"`
	Group       string `json:"group" minLength:"1"`
	Priority    int    `json:"priority" minimum:"1"`
	Status      string `json:"status" enum:"configured,checking,ready,error"`
	IPv6Blocked bool   `json:"ipv6Blocked"`
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

// AWGSaveRequest stores one validated profile and its selected group position.
type AWGSaveRequest struct {
	ID       string `json:"id" minLength:"1"`
	Group    string `json:"group" minLength:"1"`
	Priority int    `json:"priority" minimum:"1"`
	Profile  string `json:"profile" minLength:"1"`
}

// AWGUpdateRequest replaces mutable settings while the path keeps the connection ID stable.
type AWGUpdateRequest struct {
	Group    string `json:"group" minLength:"1"`
	Priority int    `json:"priority" minimum:"1"`
	Profile  string `json:"profile" minLength:"1"`
}

// AWGDeleteRequest identifies one connection for a privileged delete operation.
type AWGDeleteRequest struct {
	ID string `json:"id" minLength:"1"`
}
