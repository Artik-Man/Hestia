package panelmodel

// DomainListValues contains the editable public fields of a domain list.
type DomainListValues struct {
	Name  string   `json:"name" minLength:"1" maxLength:"80"`
	Group string   `json:"group" maxLength:"63" doc:"Пустая строка означает отсутствие привязки"`
	Masks []string `json:"masks" nullable:"false" maxItems:"1024"`
}

// DomainListUpdate compares the last observed list with the gateway before storing List.
type DomainListUpdate struct {
	Expected RuleList         `json:"expected"`
	List     DomainListValues `json:"list"`
}
