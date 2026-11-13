package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

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
type connectionOperationInput struct {
	OperationID string `path:"operationId" minLength:"36" maxLength:"36" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
}
type connectionOperationOutput struct {
	Body panelmodel.ConnectionEnabledOperation
}

// registerConnectionEnabled confirms a virtual connection state only after the privileged runtime transaction succeeds.
func registerConnectionEnabled(api huma.API, change connectionEnabler) {
	receipts := &connectionOperationReceipts{}
	huma.Register(api, huma.Operation{OperationID: "getConnectionEnabledOperation", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/connections/operations/{operationId}", Summary: "Прочитать результат операции включения подключения", Errors: []int{404, 422}}, func(_ context.Context, in *connectionOperationInput) (*connectionOperationOutput, error) {
		receipt, ok := receipts.get(in.OperationID, time.Now())
		if !ok {
			return nil, huma.Error404NotFound("Результат операции не найден")
		}
		return &connectionOperationOutput{Body: receipt}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "setConnectionEnabled", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/connections/{id}/enabled", Summary: "Включить или отключить виртуальное подключение", MaxBodyBytes: 1024, Errors: []int{404, 409, 422, 503}}, func(ctx context.Context, in *connectionEnabledInput) (*connectionEnabledOutput, error) {
		if !awg.ValidConnectionID(in.ID) {
			return nil, huma.Error422UnprocessableEntity("Недопустимый ID подключения")
		}
		if in.Body.OperationID != "" {
			receipt, start, err := receipts.begin(string(in.Body.OperationID), in.ID, in.Body.Enabled, time.Now())
			if err != nil {
				return nil, err
			}
			if !start {
				return replayConnectionOperation(receipt)
			}
		}
		var confirmed panelmodel.ConnectionEnabled
		var err error
		if change == nil {
			err = huma.Error503ServiceUnavailable("Изменение состояния подключений не включено")
		} else {
			confirmed, err = change(ctx, in.ID, in.Body.Enabled)
			if err == nil && (confirmed.ID != in.ID || confirmed.Enabled != in.Body.Enabled) {
				err = huma.Error503ServiceUnavailable("Шлюз не подтвердил состояние подключения")
			}
		}
		if in.Body.OperationID != "" {
			receipts.complete(string(in.Body.OperationID), connectionOperationStatus(err), time.Now())
		}
		if err != nil {
			return nil, err
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
