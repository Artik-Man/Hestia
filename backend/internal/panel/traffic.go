package panel

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/geoip"
	"github.com/Artik-Man/Hestia/internal/traffic"
	"github.com/danielgtaylor/huma/v2"
	"golang.org/x/text/language"
	"golang.org/x/text/language/display"
)

type trafficInput struct {
	Query    string `query:"query" doc:"Подстрока домена или адреса назначения" maxLength:"255"`
	Protocol string `query:"protocol" doc:"Протокол потока" enum:"TCP,UDP,QUIC"`
	Output   string `query:"output" doc:"connection:<ID> для выбранного подключения, blocked для блокировки или unknown для неопределённого решения" maxLength:"512"`
	From     string `query:"from" doc:"Начало периода включительно (RFC 3339)" format:"date-time"`
	Until    string `query:"until" doc:"Конец периода включительно (RFC 3339)" format:"date-time"`
	Offset   int    `query:"offset" doc:"Число пропускаемых совпадений от начала выборки" minimum:"0" maximum:"2147483647"`
	Limit    int    `query:"limit" doc:"Максимум возвращаемых строк, до 500" default:"100" minimum:"1" maximum:"500"`
	Snapshot string `query:"snapshot" doc:"Верхняя граница последовательности записей из первой страницы" maxLength:"20"`
	Country  string `query:"country" doc:"Подстрока отображаемого названия страны назначения без учёта регистра" maxLength:"255"`
}

type trafficPageOutput struct{ Body traffic.TrafficPage }
type trafficSettingsInput struct{ Body traffic.TrafficSettingsChange }

type trafficSettingsIO struct {
	Body traffic.TrafficSettings `doc:"Ограничения хранения журнала трафика"`
}

// registerTraffic exposes bounded journal windows and durable storage settings to the local panel.
func registerTraffic(api huma.API, store *traffic.Store, countries *geoip.Index, provider *geoip.Enrichment) {
	names := map[string]string{"": "Не определена"}
	for _, code := range strings.Fields(geoip.CountryCodes) {
		names[code] = display.Russian.Regions().Name(language.MustParseRegion(code))
	}
	resolve := func(address, fakeIP string) string {
		if address == "" || address == fakeIP {
			return ""
		}
		if code := provider.Country(address); code != "" {
			return code
		}
		return countries.Country(address)
	}
	huma.Register(api, huma.Operation{OperationID: "getTraffic", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/traffic", Summary: "Прочитать страницу журнала трафика", Errors: []int{422, 503}}, func(ctx context.Context, in *trafficInput) (*trafficPageOutput, error) {
		if store == nil {
			return nil, trafficError(nil)
		}
		q := traffic.Query{Text: in.Query, Protocol: in.Protocol, Output: in.Output, Offset: in.Offset, Limit: in.Limit, Snapshot: in.Snapshot}
		if term := strings.ToLower(strings.TrimSpace(in.Country)); term != "" {
			matches := make(map[string]bool)
			for code, label := range names {
				matches[code] = strings.Contains(strings.ToLower(label), term)
			}
			q.MatchCountry = func(address, fakeIP string) (string, bool) {
				code := resolve(address, fakeIP)
				return code, matches[code]
			}
		}
		var err error
		if in.From != "" {
			q.From, err = time.Parse(time.RFC3339Nano, in.From)
			if err != nil {
				return nil, trafficError(traffic.ErrQuery)
			}
		}
		if in.Until != "" {
			q.Until, err = time.Parse(time.RFC3339Nano, in.Until)
			if err != nil {
				return nil, trafficError(traffic.ErrQuery)
			}
		}
		page, err := store.Page(ctx, q)
		if err != nil {
			return nil, trafficError(err)
		}
		for i := range page.Events {
			event := &page.Events[i]
			if q.MatchCountry == nil {
				event.Country = resolve(event.Address, event.FakeIP)
			}
			if event.Country != "" {
				event.CountryName = names[event.Country]
			}
		}
		return &trafficPageOutput{Body: page}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "getTrafficSettings", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/traffic/settings", Summary: "Прочитать ограничения хранения журнала", Errors: []int{503}}, func(ctx context.Context, _ *struct{}) (*trafficSettingsIO, error) {
		if store == nil {
			return nil, trafficError(nil)
		}
		value, err := store.Settings(ctx)
		if err != nil {
			return nil, trafficError(err)
		}
		return &trafficSettingsIO{Body: value}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "updateTrafficSettings", RequestBody: &huma.RequestBody{Description: "Ограничения хранения журнала трафика"}, Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/traffic/settings", Summary: "Сохранить ограничения хранения журнала", MaxBodyBytes: 1024, Errors: []int{409, 422, 503}}, func(ctx context.Context, in *trafficSettingsInput) (*trafficSettingsIO, error) {
		if store == nil {
			return nil, trafficError(nil)
		}
		if err := store.SaveSettings(ctx, in.Body); err != nil {
			return nil, trafficError(err)
		}
		return &trafficSettingsIO{Body: in.Body.Proposed}, nil
	})
}

// trafficError maps invalid filters and storage failures to safe HTTP responses.
func trafficError(err error) error {
	if errors.Is(err, traffic.ErrSettingsConflict) {
		return huma.Error409Conflict("Настройки журнала изменились. Повторно откройте форму.")
	}
	if errors.Is(err, traffic.ErrQuery) {
		return huma.Error422UnprocessableEntity("Недопустимые параметры журнала")
	}
	if err != nil {
		log.Printf("traffic journal: %v", err)
	}
	return huma.Error503ServiceUnavailable("Хранилище журнала трафика недоступно")
}

// maintainTraffic expires on-disk history on idle gateways between collector writes.
func maintainTraffic(ctx context.Context, store *traffic.Store) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.Clean(ctx); err != nil && ctx.Err() == nil {
				log.Printf("traffic cleanup: %v", err)
			}
		}
	}
}
