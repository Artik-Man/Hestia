package panel

import (
	"context"
	"net/http"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type physicalOutput struct{ Body panelmodel.PhysicalInventory }
type wifiCreateInput struct {
	Body panelmodel.WifiConnectionSettings
}
type wifiUpdateInput struct {
	ID   string `path:"id" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
	Body panelmodel.WifiConnectionSettings
}
type wifiDeleteInput struct {
	ID string `path:"id" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"`
}
type physicalHelper func(context.Context, string, any, any) error

// registerPhysical publishes read-only hardware inventory and bounded client Wi-Fi changes through fixed root helper modes.
func registerPhysical(api huma.API, helper physicalHelper) {
	call := func(ctx context.Context, mode string, in, out any) error {
		if helper == nil {
			return huma.Error503ServiceUnavailable("Управление интерфейсами недоступно")
		}
		switch mode {
		case "-wifi-create", "-wifi-save", "-wifi-delete":
			if ctx.Err() != nil {
				return huma.Error503ServiceUnavailable("Запрос прерван до начала операции")
			}
			// Allow the 90-second gateway operation and its independent 65-second rollback to finish after disconnect.
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
			defer cancel()
		}
		if err := helper(ctx, mode, in, out); err != nil {
			if failure, ok := err.(awgHTTPFailure); ok {
				switch failure.status {
				case 404:
					return huma.Error404NotFound("Профиль Wi-Fi не найден")
				case 409:
					return huma.Error409Conflict("Интерфейс занят или конфигурация изменилась")
				case 422:
					return huma.Error422UnprocessableEntity("Недопустимые настройки Wi-Fi")
				}
			}
			return huma.Error503ServiceUnavailable("Операция с сетевым интерфейсом не подтверждена")
		}
		return nil
	}
	huma.Register(api, huma.Operation{OperationID: "listPhysicalConnections", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/physical-connections", Summary: "Получить физические интерфейсы и сохранённые Wi-Fi сети", Errors: []int{409, 503}}, func(ctx context.Context, _ *struct{}) (*physicalOutput, error) {
		var out physicalOutput
		if err := call(ctx, "-physical-list", struct{}{}, &out.Body); err != nil {
			return nil, err
		}
		return &out, nil
	})
	huma.Register(api, huma.Operation{OperationID: "createWifiConnection", Tags: []string{"Panel"}, Method: http.MethodPost, Path: "/api/wifi-connections", Summary: "Подключиться к Wi-Fi сети", MaxBodyBytes: 2048, DefaultStatus: 204, Errors: []int{409, 422, 503}}, func(ctx context.Context, in *wifiCreateInput) (*struct{}, error) {
		return nil, call(ctx, "-wifi-create", in.Body, nil)
	})
	huma.Register(api, huma.Operation{OperationID: "saveWifiConnection", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/wifi-connections/{id}", Summary: "Изменить сохранённый профиль Wi-Fi", MaxBodyBytes: 2048, DefaultStatus: 204, Errors: []int{404, 409, 422, 503}}, func(ctx context.Context, in *wifiUpdateInput) (*struct{}, error) {
		return nil, call(ctx, "-wifi-save", panelmodel.WifiSaveCommand{ID: in.ID, WifiConnectionSettings: in.Body}, nil)
	})
	huma.Register(api, huma.Operation{OperationID: "deleteWifiConnection", Tags: []string{"Panel"}, Method: http.MethodDelete, Path: "/api/wifi-connections/{id}", Summary: "Удалить сохранённый профиль Wi-Fi", DefaultStatus: 204, Errors: []int{404, 409, 422, 503}}, func(ctx context.Context, in *wifiDeleteInput) (*struct{}, error) {
		return nil, call(ctx, "-wifi-delete", panelmodel.AWGIDRequest{ID: in.ID}, nil)
	})
}
