package panelmodel

import "github.com/Artik-Man/Hestia/internal/quality"

// QualityConnection pairs one exit's measured quality with its availability and confirmed selector state.
type QualityConnection struct {
	ID        string         `json:"id"`
	Available bool           `json:"available"`
	Active    bool           `json:"active" doc:"Выход подтверждён действующим селектором группы"`
	Result    quality.Result `json:"result"`
}

// QualityGroup lists the group's connections in the order used by the selector.
type QualityGroup struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Settings    quality.GroupSettings `json:"settings"`
	Connections []QualityConnection   `json:"connections" nullable:"false"`
}

// QualityReport carries one controller observation with the settings that produced it.
type QualityReport struct {
	CapturedAt string           `json:"capturedAt" doc:"Время снимка RFC 3339. Пусто до получения актуального отчёта от контроллера."`
	Settings   quality.Settings `json:"settings"`
	Groups     []QualityGroup   `json:"groups" nullable:"false"`
}
