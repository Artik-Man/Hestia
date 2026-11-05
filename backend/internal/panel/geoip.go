package panel

import (
	"context"
	"errors"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/geoip"
	"github.com/Artik-Man/Hestia/internal/traffic"
	"github.com/danielgtaylor/huma/v2"
)

const geoIPSettingsPath = "/api/dns/geoip"

// DNSGeoIPSettings reports whether new public destinations can be submitted to 2ip.
type DNSGeoIPSettings struct {
	Configured bool `json:"configured" doc:"Ключ 2ip сохранён"`
}

// DNSGeoIPUpdate replaces the write-only 2ip token; an explicit empty value disables new requests.
type DNSGeoIPUpdate struct {
	Token string `json:"token" maxLength:"256" writeOnly:"true" doc:"Новый ключ 2ip. Пустая строка отключает запросы к сервису."`
}

type geoIPSettingsOutput struct{ Body DNSGeoIPSettings }
type geoIPSettingsInput struct{ Body DNSGeoIPUpdate }

// registerGeoIP serves write-only provider configuration without exposing credentials in errors or GET responses.
func registerGeoIP(api huma.API, provider *geoip.Enrichment) {
	huma.Register(api, huma.Operation{OperationID: "getDnsGeoip", Tags: []string{"Panel"}, Method: http.MethodGet, Path: geoIPSettingsPath, Summary: "Прочитать состояние ключа 2ip", Errors: []int{503}}, func(context.Context, *struct{}) (*geoIPSettingsOutput, error) {
		if provider == nil {
			return nil, huma.Error503ServiceUnavailable("Настройки GeoIP недоступны")
		}
		return &geoIPSettingsOutput{Body: DNSGeoIPSettings{Configured: provider.Configured()}}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "updateDnsGeoip", RequestBody: &huma.RequestBody{Description: "Ключ для фоновых запросов GeoIP"}, Tags: []string{"Panel"}, Method: http.MethodPut, Path: geoIPSettingsPath, Summary: "Заменить или удалить ключ 2ip", MaxBodyBytes: 2048, Errors: []int{422, 503}}, func(_ context.Context, in *geoIPSettingsInput) (*geoIPSettingsOutput, error) {
		if provider == nil {
			return nil, huma.Error503ServiceUnavailable("Настройки GeoIP недоступны")
		}
		err := provider.SetToken(in.Body.Token)
		if errors.Is(err, geoip.ErrToken) {
			return nil, huma.Error422UnprocessableEntity("Недопустимый ключ 2ip")
		}
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось сохранить настройки GeoIP")
		}
		return &geoIPSettingsOutput{Body: DNSGeoIPSettings{Configured: provider.Configured()}}, nil
	})
}

// enrichedJournal forwards freshly committed numeric destinations to the bounded background queue.
type enrichedJournal struct {
	*traffic.Store
	provider *geoip.Enrichment
}

// AppendBatch commits observations before submitting real destinations, ignoring opaque FakeIPs and domains.
func (j enrichedJournal) AppendBatch(ctx context.Context, events []traffic.TrafficEvent) error {
	if err := j.Store.AppendBatch(ctx, events); err != nil {
		return err
	}
	for _, e := range events {
		if e.Address != "" && e.Address != e.FakeIP {
			j.provider.Observe(e.Address)
		}
	}
	return nil
}
