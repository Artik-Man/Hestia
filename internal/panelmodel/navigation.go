package panelmodel

// Navigation contains the configured external destinations available in the panel menu.
type Navigation struct {
	GrafanaURL string `json:"grafanaUrl" doc:"Адрес Grafana по HTTPS или пустая строка, если интеграция выключена"`
}
