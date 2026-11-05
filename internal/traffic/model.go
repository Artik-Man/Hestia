// Package traffic maintains the persistent gateway traffic journal.
package traffic

import "time"

const (
	Observed         = "observed"
	Unconfirmed      = "unconfirmed"
	Blocked          = "blocked"
	ConnectionFilter = "connection:"
)

// TrafficEvent holds facts known when a flow was recorded; optional evidence is omitted when unavailable.
type TrafficEvent struct {
	ID               string    `json:"id"`
	Time             time.Time `json:"time"`
	Protocol         string    `json:"protocol" enum:"TCP,UDP"`
	Address          string    `json:"address"`
	Port             int       `json:"port" minimum:"0" maximum:"65535"`
	Domain           string    `json:"domain,omitempty"`
	FakeIP           string    `json:"fakeIP,omitempty"`
	Group            string    `json:"group,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	Kind             string    `json:"kind" enum:"observed,unconfirmed,blocked"`
	BlockReason      string    `json:"blockReason,omitempty"`
	Connection       string    `json:"connection,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	NetworkInterface string    `json:"networkInterface,omitempty"`
	FirstReplyMs     *int      `json:"firstReplyMs,omitempty"`
	DNSQueryID       string    `json:"dnsQueryId,omitempty"`
}

// TrafficSettings specifies independent age and on-disk limits for the journal.
type TrafficSettings struct {
	MaxMB          int `json:"maxMB" doc:"Лимит файла журнала в мегабайтах (1 МБ = 1048576 байт)" minimum:"1" maximum:"1048576"`
	RetentionHours int `json:"retentionHours" doc:"Срок хранения от времени события в часах" minimum:"1" maximum:"87600"`
}

// TrafficSettingsChange describes the settings seen on open and the limits confirmed in the dialog.
type TrafficSettingsChange struct {
	Expected TrafficSettings `json:"expected" doc:"Настройки, прочитанные при открытии формы"`
	Proposed TrafficSettings `json:"proposed" doc:"Новые значения, подтверждённые оператором"`
}

// TrafficPage contains one bounded window and options derived from the entire selected period.
type TrafficPage struct {
	Events           []TrafficEvent `json:"events" nullable:"false"`
	Total            int            `json:"total"`
	Outputs          []string       `json:"outputs" nullable:"false"`
	Snapshot         string         `json:"snapshot"`
	Lost             int64          `json:"lost"`
	LastInterruption *time.Time     `json:"lastInterruption,omitempty" doc:"Время последнего обнаруженного разрыва подписки на трафик (UTC); число пропущенных в этот период потоков неизвестно"`
	SourceAvailable  bool           `json:"sourceAvailable"`
}

// Query intersects the selected time interval with optional filters and a stable ingest high-water mark.
type Query struct {
	From, Until                      time.Time
	Text, Protocol, Output, Snapshot string
	Offset, Limit                    int
}
