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

// DNSGeoIPSettings reports the current 2ip key and whether enrichment is enabled.
type DNSGeoIPSettings struct {
	Token      string `json:"token" maxLength:"256" doc:"Сохранённый ключ 2ip или пустая строка, если ключ не задан."`
	Configured bool   `json:"configured" doc:"Ключ 2ip сохранён"`
}

// DNSGeoIPUpdate replaces the saved 2ip token; an explicit empty value disables new requests.
type DNSGeoIPUpdate struct {
	Token string `json:"token" maxLength:"256" doc:"Новый ключ 2ip. Пустая строка отключает запросы к сервису."`
}

type geoIPSettingsOutput struct{ Body DNSGeoIPSettings }
type geoIPSettingsInput struct{ Body DNSGeoIPUpdate }

// geoIPSettings returns the token and its configured flag from a single saved value.
func geoIPSettings(token string) *geoIPSettingsOutput {
	return &geoIPSettingsOutput{Body: DNSGeoIPSettings{Token: token, Configured: token != ""}}
}

// registerGeoIP serves the saved provider key to the settings panel and omits it from errors.
func registerGeoIP(api huma.API, provider *geoip.Enrichment) {
	huma.Register(api, huma.Operation{OperationID: "getDnsGeoip", Tags: []string{"Panel"}, Method: http.MethodGet, Path: geoIPSettingsPath, Summary: "Прочитать сохранённый ключ 2ip", Errors: []int{503}}, func(context.Context, *struct{}) (*geoIPSettingsOutput, error) {
		if provider == nil {
			return nil, huma.Error503ServiceUnavailable("Настройки GeoIP недоступны")
		}
		return geoIPSettings(provider.Token()), nil
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
		return geoIPSettings(provider.Token()), nil
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
