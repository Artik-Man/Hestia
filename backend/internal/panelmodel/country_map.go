package panelmodel

// CountryMap is a complete gateway policy and its opaque compare-and-set token.
type CountryMap struct {
	Enabled     bool              `json:"enabled"`
	Assignments map[string]string `json:"assignments" nullable:"false" minProperties:"249" maxProperties:"249"`
	Version     string            `json:"version" minLength:"1" maxLength:"64"`
}
