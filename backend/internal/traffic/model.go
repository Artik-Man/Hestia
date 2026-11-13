// Package traffic maintains the persistent gateway traffic journal.
package traffic

import "time"

const (
	Observed         = "observed"
	Unconfirmed      = "unconfirmed"
	Blocked          = "blocked"
	ConnectionFilter = "connection:"
	UnknownOutput    = "unknown"
	MaxTraceStages   = 16
)

// TrafficEvent holds facts known when a flow was recorded; optional evidence is omitted when unavailable.
type TrafficEvent struct {
	ID               string         `json:"id"`
	Time             time.Time      `json:"time"`
	Protocol         string         `json:"protocol" enum:"TCP,UDP,QUIC"`
	Address          string         `json:"address"`
	Country          string         `json:"country,omitempty" pattern:"^[A-Z]{2}$" doc:"Страна реального IP назначения по текущей базе GeoIP (ISO 3166-1 alpha-2)"`
	CountryName      string         `json:"countryName,omitempty" doc:"Название страны на русском языке для отображения и текстового поиска"`
	Port             int            `json:"port" minimum:"0" maximum:"65535"`
	Domain           string         `json:"domain,omitempty"`
	FakeIP           string         `json:"fakeIP,omitempty"`
	Group            string         `json:"group,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	Kind             string         `json:"kind" enum:"observed,unconfirmed,blocked"`
	BlockReason      string         `json:"blockReason,omitempty"`
	Connection       string         `json:"connection,omitempty"`
	Namespace        string         `json:"namespace,omitempty"`
	NetworkInterface string         `json:"networkInterface,omitempty"`
	FirstReplyMs     *int           `json:"firstReplyMs,omitempty"`
	DNSQueryID       string         `json:"dnsQueryId,omitempty"`
	Trace            *TraceEvidence `json:"trace,omitempty"`
}

// TraceEvidence stores one opt-in, tuple-filtered diagnostic summary without packet contents.
type TraceEvidence struct {
	SessionID               string                `json:"sessionId"`
	StartedAt               time.Time             `json:"startedAt"`
	ConfigurationObservedAt *time.Time            `json:"configurationObservedAt,omitempty" doc:"UTC-время начала read-only снимка назначения клиента, policy, RPDB и маршрутов перед сбором tuple"`
	DurationMs              int                   `json:"durationMs"`
	PolicyKey               string                `json:"policyKey,omitempty" pattern:"^Policy[0-9]{1,10}$" minLength:"7" maxLength:"16" doc:"Явная per-client policy, разрешённая из read-only client inventory и configuration snapshot"`
	ConfiguredMark          uint32                `json:"configuredMark,omitempty" minimum:"0" maximum:"268435455" doc:"Mark из read-only RCI snapshot выбранной политики"`
	NDMTable                uint32                `json:"ndmTable,omitempty" minimum:"0" maximum:"65535" doc:"Таблица NDM из read-only RCI snapshot"`
	HestiaTable             uint32                `json:"hestiaTable,omitempty" minimum:"0" maximum:"65535" doc:"Таблица Hestia, рассчитанная из mark; наличие объектов подтверждают отдельные стадии"`
	Source                  string                `json:"source"`
	SourcePort              int                   `json:"sourcePort"`
	Destination             string                `json:"destination"`
	DestinationPort         int                   `json:"destinationPort"`
	NDMConntrack            *NDMConntrackEvidence `json:"ndmConntrack,omitempty" doc:"Bounded exact-tuple read-only NDM conntrack observation; mark is the connection mark, not a packet mark verdict"`
	Stages                  []TraceStage          `json:"stages" maxItems:"16"`
}

// NDMConntrackEvidence stores allowlisted fields from one exact tuple in the NDM conntrack table.
type NDMConntrackEvidence struct {
	Status          string    `json:"status" enum:"observed,not_observed,unavailable,truncated"`
	ObservedAt      time.Time `json:"observedAt" format:"date-time"`
	Detail          string    `json:"detail,omitempty" maxLength:"160"`
	OriginalPackets *uint64   `json:"originalPackets,omitempty"`
	OriginalBytes   *uint64   `json:"originalBytes,omitempty"`
	ReplyPackets    *uint64   `json:"replyPackets,omitempty"`
	ReplyBytes      *uint64   `json:"replyBytes,omitempty"`
	Mark            *uint64   `json:"mark,omitempty" maximum:"4294967295" doc:"Observed uint32 conntrack mark; not direct skb->mark or RPDB lookup evidence"`
	NDMMark         *uint64   `json:"ndmMark,omitempty" maximum:"4294967295"`
	IFL             *uint32   `json:"ifl,omitempty" doc:"Raw NDM conntrack ifl interface index"`
	IFW             *uint32   `json:"ifw,omitempty" doc:"Raw NDM conntrack ifw interface index"`
	IFLName         string    `json:"iflName,omitempty" enum:"br0,opkgtun0"`
	IFWName         string    `json:"ifwName,omitempty" enum:"br0,opkgtun0"`
	Flags           []string  `json:"flags,omitempty" maxItems:"4" doc:"Allowlisted conntrack flags only"`
}

// TraceStage records either a direct observation, an explicit lack of observation, or a configuration-only expectation.
type TraceStage struct {
	Name         string `json:"name"`
	Status       string `json:"status" enum:"observed,not_observed,configured_expectation,unavailable,truncated"`
	Detail       string `json:"detail,omitempty"`
	Count        int    `json:"count,omitempty"`
	ReverseCount int    `json:"reverseCount,omitempty"`
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
	// MatchCountry resolves a destination to its current country code and whether it matches the active filter.
	MatchCountry func(address, fakeIP string) (code string, matches bool)
}
