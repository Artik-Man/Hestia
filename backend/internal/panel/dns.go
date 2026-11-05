package panel

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"github.com/danielgtaylor/huma/v2"
)

// DNSPolicySnapshot contains the independently versioned durable policy accepted by the panel.
type DNSPolicySnapshot struct {
	Revision int              `json:"revision" minimum:"0"`
	Policy   dnspolicy.Policy `json:"policy"`
}

// DNSPolicyUpdate atomically replaces the settings and both lists at the expected revision.
type DNSPolicyUpdate struct {
	ExpectedRevision int              `json:"expectedRevision" minimum:"0"`
	Policy           dnspolicy.Policy `json:"policy"`
}

type dnsPolicyOutput struct{ Body DNSPolicySnapshot }
type dnsPolicyInput struct{ Body DNSPolicyUpdate }
type dnsWarmOutput struct{ Body dnspolicy.DNSWarmReport }

// dnsPolicyResponse maps verified store outcomes into the public DNS policy contract.
func dnsPolicyResponse(s dnspolicy.Snapshot, err error) (*dnsPolicyOutput, error) {
	switch {
	case errors.Is(err, dnspolicy.ErrConflict):
		return nil, huma.Error409Conflict("Настройки DNS уже изменились. Обновите страницу и повторите изменение.")
	case errors.Is(err, dnspolicy.ErrInvalid):
		return nil, huma.Error422UnprocessableEntity("Проверьте параметры прогрева, домены и окно выдачи после TTL.")
	case err != nil:
		return nil, huma.Error503ServiceUnavailable("Хранилище настроек DNS недоступно.")
	default:
		return &dnsPolicyOutput{Body: DNSPolicySnapshot{Revision: s.Revision, Policy: s.Policy}}, nil
	}
}

// registerDNS serves durable policy and independent observations using the same typed operations for documentation and runtime.
func registerDNS(api huma.API, path string, reportPath string) {
	store := dnspolicy.Store{Path: path}
	huma.Register(api, huma.Operation{OperationID: "getDnsPolicy", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/dns/policy", Summary: "Прочитать сохранённые настройки DNS и списки прогрева", Errors: []int{503}},
		func(_ context.Context, _ *struct{}) (*dnsPolicyOutput, error) {
			if path == "" {
				return nil, huma.Error503ServiceUnavailable("Хранилище настроек DNS не настроено.")
			}
			return dnsPolicyResponse(store.Read())
		})
	huma.Register(api, huma.Operation{OperationID: "updateDnsPolicy", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/dns/policy", Summary: "Сохранить настройки DNS и списки при совпадении ревизии", MaxBodyBytes: 3 << 20, Errors: []int{409, 413, 422, 503}},
		func(_ context.Context, in *dnsPolicyInput) (*dnsPolicyOutput, error) {
			if path == "" {
				return nil, huma.Error503ServiceUnavailable("Запись настроек DNS не включена.")
			}
			return dnsPolicyResponse(store.Apply(in.Body.ExpectedRevision, in.Body.Policy))
		})
	huma.Register(api, huma.Operation{OperationID: "getDnsWarm", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/dns/warm", Summary: "Прочитать наблюдаемый список автоматического прогрева", Errors: []int{503}},
		func(_ context.Context, _ *struct{}) (*dnsWarmOutput, error) {
			report, err := dnspolicy.ReadWarmReport(reportPath, time.Now())
			if err != nil {
				return nil, huma.Error503ServiceUnavailable("Наблюдения службы DNS недоступны.")
			}
			return &dnsWarmOutput{Body: report}, nil
		})
}
