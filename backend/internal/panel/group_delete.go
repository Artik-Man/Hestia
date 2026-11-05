package panel

import (
	"context"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type groupDeleter func(context.Context, string) error

type groupDeleteInput struct {
	ID string `path:"id" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
}

// registerGroupDelete confirms deletion only after the gateway protects the current default and unbinds lists from the empty group.
func registerGroupDelete(api huma.API, remove groupDeleter) {
	huma.Register(api, huma.Operation{
		OperationID: "deleteGroup", Tags: []string{"Panel"}, Method: http.MethodDelete, Path: "/api/groups/{id}",
		Summary: "Удалить пустую группу подключений и снять привязки её списков", DefaultStatus: http.StatusNoContent,
		Errors: []int{http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *groupDeleteInput) (*struct{}, error) {
		if binding.ValidateGroupID(in.ID) != nil {
			return nil, huma.Error422UnprocessableEntity("Недопустимый ID группы")
		}
		if remove == nil {
			return nil, huma.Error503ServiceUnavailable("Удаление групп не включено")
		}
		if err := remove(ctx, in.ID); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// deleteInstalledGroup submits the stable routing ID to the fixed deletion helper through stdin.
func deleteInstalledGroup(ctx context.Context, id string) error {
	return runInstalledChange(ctx, "-delete-group", panelmodel.GroupDeleteCommand{ID: id})
}
