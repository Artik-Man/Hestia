package panelmodel

// ConnectionEnabledRequest sets administrative availability independently of probe health.
type ConnectionEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// ConnectionEnabled confirms the committed state of one stable virtual connection ID.
type ConnectionEnabled struct {
	ID      string `json:"id" minLength:"1" maxLength:"63"`
	Enabled bool   `json:"enabled"`
}
