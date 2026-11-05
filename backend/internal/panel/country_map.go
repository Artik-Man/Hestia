package panel

import (
	"context"
	"errors"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// countryMapAccess reads on nil input or conditionally replaces the complete gateway policy.
type countryMapAccess func(*panelmodel.CountryMap) (panelmodel.CountryMap, error)
type countryMapMessage struct{ Body panelmodel.CountryMap }

// registerCountryMap exposes the gateway's durable assignments with versioned whole-policy writes.
func registerCountryMap(api huma.API, access countryMapAccess) {
	invoke := func(change *panelmodel.CountryMap) (*countryMapMessage, error) {
		if access == nil {
			return nil, huma.Error503ServiceUnavailable("Хранилище маршрутов по странам недоступно")
		}
		policy, err := access(change)
		switch {
		case errors.Is(err, binding.ErrConflict):
			return nil, huma.Error409Conflict("Настройки изменились или выполняется другая операция")
		case errors.Is(err, binding.ErrInvalidCountryMap):
			return nil, huma.Error422UnprocessableEntity("Назначьте каждой стране существующую группу")
		case err != nil:
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать или сохранить маршруты по странам")
		}
		return &countryMapMessage{Body: policy}, nil
	}
	huma.Register(api, huma.Operation{OperationID: "getCountryMap", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/country-map", Summary: "Прочитать маршруты по странам", Errors: []int{409, 503}}, func(_ context.Context, _ *struct{}) (*countryMapMessage, error) { return invoke(nil) })
	huma.Register(api, huma.Operation{OperationID: "updateCountryMap", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/country-map", Summary: "Сохранить маршруты по странам", MaxBodyBytes: 128 << 10, Errors: []int{409, 413, 422, 503}}, func(_ context.Context, in *countryMapMessage) (*countryMapMessage, error) { return invoke(&in.Body) })
}
