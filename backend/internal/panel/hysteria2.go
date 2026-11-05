package panel

import (
	"context"
	"net/http"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

const hysteriaPath = "/api/hysteria2"

type hysteriaCreateInput struct {
	Body panelmodel.Hysteria2WriteRequest
}
type hysteriaUpdateInput struct {
	ID   string `path:"id" format:"uuid"`
	Body panelmodel.Hysteria2WriteRequest
}
type hysteriaIDInput struct {
	ID string `path:"id" format:"uuid"`
}
type hysteriaOutput struct {
	Body panelmodel.Hysteria2Connection
}
type hysteriaProfileOutput struct {
	Body panelmodel.Hysteria2ConnectionProfile
}

type hysteriaListOutput struct {
	Body []panelmodel.Hysteria2Connection `nullable:"false"`
}

// registerHysteria2 exposes single-port profiles and sends bounded mutations to the installed gateway.
func registerHysteria2(api huma.API, helper physicalHelper) {
	call := func(ctx context.Context, mode string, in, out any) error {
		if helper == nil || ctx.Err() != nil {
			return huma.Error503ServiceUnavailable("Управление Hysteria 2 недоступно")
		}
		if mode != "-hysteria2-list" && mode != "-hysteria2-read" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), 4*time.Minute)
			defer cancel()
		}
		if err := helper(ctx, mode, in, out); err != nil {
			if failure, ok := err.(awgHTTPFailure); ok {
				switch failure.status {
				case 404:
					return huma.Error404NotFound("Подключение или группа не найдены")
				case 409:
					return huma.Error409Conflict("Конфигурация занята или изменилась")
				case 422:
					return huma.Error422UnprocessableEntity("Недопустимые настройки Hysteria 2")
				}
			}
			return huma.Error503ServiceUnavailable("Операция Hysteria 2 не подтверждена")
		}
		return nil
	}
	save := func(ctx context.Context, id string, req panelmodel.Hysteria2WriteRequest, update bool) (*hysteriaOutput, error) {
		if err := panelmodel.ValidateHysteria2(req, update); err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		mode := "-hysteria2-create"
		if update {
			mode = "-hysteria2-update"
		}
		var result hysteriaOutput
		if err := call(ctx, mode, panelmodel.Hysteria2Command{ID: id, Hysteria2WriteRequest: req}, &result.Body); err != nil {
			return nil, err
		}
		return &result, nil
	}
	huma.Register(api, huma.Operation{OperationID: "listHysteria2Connections", Tags: []string{"Panel"}, Method: http.MethodGet, Path: hysteriaPath, Summary: "Получить подключения Hysteria 2 без паролей", Errors: []int{409, 503}}, func(ctx context.Context, _ *struct{}) (*hysteriaListOutput, error) {
		var result hysteriaListOutput
		if err := call(ctx, "-hysteria2-list", struct{}{}, &result.Body); err != nil {
			return nil, err
		}
		return &result, nil
	})
	huma.Register(api, huma.Operation{OperationID: "getHysteria2ConnectionProfile", Tags: []string{"Panel"}, Method: http.MethodGet, Path: hysteriaPath + "/{id}", Summary: "Открыть сохранённое подключение Hysteria 2, включая пароль", Errors: []int{404, 409, 503}}, func(ctx context.Context, in *hysteriaIDInput) (*hysteriaProfileOutput, error) {
		var result hysteriaProfileOutput
		if err := call(ctx, "-hysteria2-read", panelmodel.AWGIDRequest{ID: in.ID}, &result.Body); err != nil {
			return nil, err
		}
		if result.Body.ID != in.ID || result.Body.Password == "" {
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать профиль Hysteria 2")
		}
		return &result, nil
	})
	huma.Register(api, huma.Operation{OperationID: "createHysteria2Connection", Tags: []string{"Panel"}, Method: http.MethodPost, Path: hysteriaPath, Summary: "Добавить подключение Hysteria 2 в группу", MaxBodyBytes: maxAWGRequestBytes, Errors: []int{404, 409, 413, 422, 503}}, func(ctx context.Context, in *hysteriaCreateInput) (*hysteriaOutput, error) {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось создать идентификатор")
		}
		return save(ctx, id.String(), in.Body, false)
	})
	huma.Register(api, huma.Operation{OperationID: "updateHysteria2Connection", Tags: []string{"Panel"}, Method: http.MethodPut, Path: hysteriaPath + "/{id}", Summary: "Изменить настройки подключения Hysteria 2", MaxBodyBytes: maxAWGRequestBytes, Errors: []int{404, 409, 413, 422, 503}}, func(ctx context.Context, in *hysteriaUpdateInput) (*hysteriaOutput, error) {
		return save(ctx, in.ID, in.Body, true)
	})
	huma.Register(api, huma.Operation{OperationID: "deleteHysteria2Connection", Tags: []string{"Panel"}, Method: http.MethodDelete, Path: hysteriaPath + "/{id}", Summary: "Удалить подключение Hysteria 2", DefaultStatus: 204, Errors: []int{404, 409, 503}}, func(ctx context.Context, in *hysteriaIDInput) (*struct{}, error) {
		return nil, call(ctx, "-hysteria2-delete", panelmodel.AWGIDRequest{ID: in.ID}, nil)
	})
}
