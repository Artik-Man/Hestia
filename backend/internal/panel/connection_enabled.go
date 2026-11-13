package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type connectionEnabler func(context.Context, string, bool) (panelmodel.ConnectionEnabled, error)
type connectionEnabledInput struct {
	ID   string `path:"id" minLength:"1" maxLength:"63"`
	Body panelmodel.ConnectionEnabledRequest
}
type connectionEnabledOutput struct{ Body panelmodel.ConnectionEnabled }

// registerConnectionEnabled confirms a virtual connection state only after the privileged runtime transaction succeeds.
func registerConnectionEnabled(api huma.API, change connectionEnabler) {
	huma.Register(api, huma.Operation{OperationID: "setConnectionEnabled", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/connections/{id}/enabled", Summary: "Включить или отключить виртуальное подключение", MaxBodyBytes: 1024, Errors: []int{404, 409, 422, 503}}, func(ctx context.Context, in *connectionEnabledInput) (*connectionEnabledOutput, error) {
		if !awg.ValidConnectionID(in.ID) {
			return nil, huma.Error422UnprocessableEntity("Недопустимый ID подключения")
		}
		if change == nil {
			return nil, huma.Error503ServiceUnavailable("Изменение состояния подключений не включено")
		}
		confirmed, err := change(ctx, in.ID, in.Body.Enabled)
		if err != nil {
			return nil, err
		}
		if confirmed.ID != in.ID || confirmed.Enabled != in.Body.Enabled {
			return nil, huma.Error503ServiceUnavailable("Шлюз не подтвердил состояние подключения")
		}
		return &connectionEnabledOutput{Body: confirmed}, nil
	})
}

// setInstalledConnectionEnabled checks the helper's public acknowledgement of a committed runtime generation.
func setInstalledConnectionEnabled(ctx context.Context, id string, enabled bool) (panelmodel.ConnectionEnabled, error) {
	var output bytes.Buffer
	var confirmed panelmodel.ConnectionEnabled
	request := panelmodel.ConnectionEnabled{ID: id, Enabled: enabled}
	if err := runInstalledHelper(ctx, "-set-connection-enabled", request, &output); err != nil {
		return confirmed, err
	}
	if json.Unmarshal(output.Bytes(), &confirmed) != nil || confirmed != request {
		return panelmodel.ConnectionEnabled{}, huma.Error503ServiceUnavailable("Шлюз не подтвердил состояние подключения")
	}
	return confirmed, nil
}
