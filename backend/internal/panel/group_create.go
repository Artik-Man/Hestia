package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type groupCreator func(context.Context, panelmodel.GroupCreateRequest) (panelmodel.GroupIdentifier, error)
type groupRenamer func(context.Context, string, string) error
type groupCreateInput struct{ Body panelmodel.GroupCreateRequest }
type groupCreateOutput struct{ Body panelmodel.GroupIdentifier }

// registerGroupCreate publishes creation of an empty group, returning its ID after gateway confirmation.
func registerGroupCreate(api huma.API, create groupCreator) {
	huma.Register(api, huma.Operation{
		OperationID: "createGroup", Tags: []string{"Panel"}, Method: http.MethodPost, Path: "/api/groups",
		Summary: "Создать пустую группу подключений", MaxBodyBytes: 1024, DefaultStatus: http.StatusCreated,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *groupCreateInput) (*groupCreateOutput, error) {
		if (in.Body.ID == nil) == (in.Body.Name == nil) || (in.Body.ID != nil && binding.ValidateGroupID(*in.Body.ID) != nil) || (in.Body.Name != nil && binding.ValidateGroupName(*in.Body.Name) != nil) {
			return nil, huma.Error422UnprocessableEntity("Укажите допустимое название или свободный ID группы")
		}
		if create == nil {
			return nil, huma.Error503ServiceUnavailable("Создание групп не включено")
		}
		confirmed, err := create(ctx, in.Body)
		if err != nil {
			return nil, err
		}
		return &groupCreateOutput{Body: confirmed}, nil
	})
}

// createInstalledGroup captures the committed ID and verifies that the helper acknowledged the submitted name or explicit ID.
func createInstalledGroup(ctx context.Context, group panelmodel.GroupCreateRequest) (panelmodel.GroupIdentifier, error) {
	var data bytes.Buffer
	var confirmed panelmodel.GroupIdentifier
	if err := runInstalledHelper(ctx, "-create-group", group, &data); err != nil {
		return confirmed, err
	}
	if json.Unmarshal(data.Bytes(), &confirmed) != nil || binding.ValidateGroupID(confirmed.ID) != nil ||
		(group.Name != nil && confirmed.Name != *group.Name) || (group.ID != nil && confirmed.ID != *group.ID) {
		return panelmodel.GroupIdentifier{}, huma.Error503ServiceUnavailable("Шлюз не подтвердил создание группы")
	}
	return confirmed, nil
}

type groupRenameInput struct {
	ID   string `path:"id" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Body panelmodel.GroupName
}

// registerGroupRename updates the display name of a stable routing group and confirms the stored name.
func registerGroupRename(api huma.API, rename groupRenamer) {
	huma.Register(api, huma.Operation{
		OperationID: "renameGroup", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/groups/{id}",
		Summary: "Изменить название группы подключений", MaxBodyBytes: 1024,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *groupRenameInput) (*groupCreateOutput, error) {
		if binding.ValidateGroupID(in.ID) != nil || binding.ValidateGroupName(in.Body.Name) != nil {
			return nil, huma.Error422UnprocessableEntity("Недопустимое название или ID группы")
		}
		if rename == nil {
			return nil, huma.Error503ServiceUnavailable("Изменение названий групп не включено")
		}
		if err := rename(ctx, in.ID, in.Body.Name); err != nil {
			return nil, err
		}
		return &groupCreateOutput{Body: panelmodel.GroupIdentifier{ID: in.ID, Name: in.Body.Name}}, nil
	})
}

// renameInstalledGroup invokes the fixed helper mode, passing the stable ID and new display name on stdin.
func renameInstalledGroup(ctx context.Context, id, name string) error {
	return runInstalledChange(ctx, "-rename-group", panelmodel.GroupIdentifier{ID: id, Name: name})
}

type directRenameOutput struct {
	Body panelmodel.AWGUnderlayCandidate
}

// registerDirectRename validates a direct exit display name and returns the confirmed catalog entry.
func registerDirectRename(api huma.API, rename groupRenamer) {
	huma.Register(api, huma.Operation{OperationID: "renameDirectConnection", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/connections/{id}/name", Summary: "Переименовать прямое подключение", MaxBodyBytes: 1024, Errors: []int{404, 409, 422, 503}}, func(ctx context.Context, in *groupRenameInput) (*directRenameOutput, error) {
		if binding.ValidateGroupID(in.ID) != nil || binding.ValidateGroupName(in.Body.Name) != nil {
			return nil, huma.Error422UnprocessableEntity("Недопустимое имя подключения")
		}
		if rename == nil {
			return nil, huma.Error503ServiceUnavailable("Переименование подключений отключено")
		}
		if err := rename(ctx, in.ID, in.Body.Name); err != nil {
			return nil, err
		}
		return &directRenameOutput{Body: panelmodel.AWGUnderlayCandidate{ID: in.ID, Type: "direct", Name: in.Body.Name}}, nil
	})
}

// renameInstalledDirect invokes the fixed direct-only helper using bounded JSON on stdin.
func renameInstalledDirect(ctx context.Context, id, name string) error {
	return runInstalledChange(ctx, "-rename-direct", panelmodel.GroupIdentifier{ID: id, Name: name})
}
