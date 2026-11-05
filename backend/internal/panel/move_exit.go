package panel

import (
	"context"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type exitMover func(context.Context, panelmodel.ExitMoveCommand) error
type moveExitInput struct {
	ID   string `path:"id" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Body panelmodel.ExitGroupChange
}
type moveExitOutput struct {
	Body panelmodel.ExitGroupAssignment
}

// registerMoveExit exposes a conditional group assignment, returning the new membership only after the gateway confirms it.
func registerMoveExit(api huma.API, move exitMover) {
	huma.Register(api, huma.Operation{
		OperationID: "moveExit", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/connections/{id}/group",
		Summary: "Перенести подключение в другую группу", MaxBodyBytes: 1024,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *moveExitInput) (*moveExitOutput, error) {
		if binding.ValidateGroupID(in.ID) != nil || binding.ValidateGroupID(in.Body.ExpectedGroup) != nil || binding.ValidateGroupID(in.Body.Group) != nil {
			return nil, huma.Error422UnprocessableEntity("Некорректный ID подключения или группы")
		}
		if move == nil {
			return nil, huma.Error503ServiceUnavailable("Перенос подключений не включён")
		}
		if err := move(ctx, panelmodel.ExitMoveCommand{ID: in.ID, ExitGroupChange: in.Body}); err != nil {
			return nil, err
		}
		return &moveExitOutput{Body: panelmodel.ExitGroupAssignment{ID: in.ID, Group: in.Body.Group, Priority: in.Body.Priority}}, nil
	})
}

// moveInstalledExit passes the stable identifiers and destination position on stdin to the fixed installed helper.
func moveInstalledExit(ctx context.Context, change panelmodel.ExitMoveCommand) error {
	return runInstalledChange(ctx, "-move-exit", change)
}
