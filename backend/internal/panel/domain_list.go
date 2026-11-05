package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

type domainListCreator func(context.Context, panelmodel.DomainListValues) (panelmodel.RuleList, error)
type domainListUpdater func(context.Context, string, panelmodel.DomainListUpdate) (panelmodel.RuleList, error)
type domainListDeleter func(context.Context, panelmodel.RuleList) error
type domainListDeleteInput struct {
	ID   string `path:"id" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Body panelmodel.RuleList
}
type domainListCreateInput struct{ Body panelmodel.DomainListValues }
type domainListUpdateInput struct {
	ID   string `path:"id" minLength:"1" maxLength:"63" pattern:"^[a-z][a-z0-9-]{0,62}$"`
	Body panelmodel.DomainListUpdate
}
type domainListOutput struct{ Body panelmodel.RuleList }

// registerDomainLists exposes confirmed creation and conditional updates and deletion of domain lists.
func registerDomainLists(api huma.API, create domainListCreator, update domainListUpdater, remove domainListDeleter) {
	failures := []int{http.StatusRequestEntityTooLarge, http.StatusConflict, http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusServiceUnavailable}
	huma.Register(api, huma.Operation{
		OperationID: "createDomainList", Tags: []string{"Panel"}, Path: "/api/domain-lists", Method: http.MethodPost,
		Summary: "Создать и применить доменный список", DefaultStatus: http.StatusCreated, MaxBodyBytes: 1 << 20, Errors: failures,
	}, func(ctx context.Context, in *domainListCreateInput) (*domainListOutput, error) {
		if binding.ValidateDomainListValues(in.Body) != nil {
			return nil, huma.Error422UnprocessableEntity("Недопустимое название, группа или маски списка")
		}
		if create == nil {
			return nil, huma.Error503ServiceUnavailable("Запись доменных списков не включена")
		}
		saved, err := create(ctx, in.Body)
		if err != nil {
			return nil, err
		}
		return &domainListOutput{Body: saved}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "updateDomainList", Tags: []string{"Panel"}, Path: "/api/domain-lists/{id}", Method: http.MethodPut,
		Summary: "Применить изменения доменного списка при совпадении исходных значений", MaxBodyBytes: 1 << 20, Errors: failures,
	}, func(ctx context.Context, in *domainListUpdateInput) (*domainListOutput, error) {
		if in.ID != in.Body.Expected.ID || binding.ValidateDomainListValues(in.Body.List) != nil {
			return nil, huma.Error422UnprocessableEntity("Недопустимые данные доменного списка")
		}
		if update == nil {
			return nil, huma.Error503ServiceUnavailable("Запись доменных списков не включена")
		}
		saved, err := update(ctx, in.ID, in.Body)
		if err != nil {
			return nil, err
		}
		return &domainListOutput{Body: saved}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "deleteDomainList", Tags: []string{"Panel"}, Path: "/api/domain-lists/{id}", Method: http.MethodDelete,
		Summary: "Удалить доменный список при совпадении исходных значений", DefaultStatus: http.StatusNoContent, MaxBodyBytes: 1 << 20, Errors: failures,
	}, func(ctx context.Context, in *domainListDeleteInput) (*struct{}, error) {
		if in.ID != in.Body.ID {
			return nil, huma.Error422UnprocessableEntity("ID не совпадает с исходным списком")
		}
		if remove == nil {
			return nil, huma.Error503ServiceUnavailable("Запись доменных списков не включена")
		}
		if err := remove(ctx, in.Body); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// createInstalledDomainList returns the gateway-assigned stable ID only after the installed helper confirms all values.
func createInstalledDomainList(ctx context.Context, values panelmodel.DomainListValues) (panelmodel.RuleList, error) {
	var data bytes.Buffer
	if err := runInstalledHelper(ctx, "-create-domain-list", values, &data); err != nil {
		return panelmodel.RuleList{}, err
	}
	return confirmedDomainList(data.Bytes(), "", values)
}

// updateInstalledDomainList forwards the expected snapshot and checks that the helper confirmed the same stable list.
func updateInstalledDomainList(ctx context.Context, id string, change panelmodel.DomainListUpdate) (panelmodel.RuleList, error) {
	var data bytes.Buffer
	if err := runInstalledHelper(ctx, "-update-domain-list", change, &data); err != nil {
		return panelmodel.RuleList{}, err
	}
	return confirmedDomainList(data.Bytes(), id, change.List)
}

// confirmedDomainList accepts a typed helper result only when it acknowledges the requested list values and binding state.
func confirmedDomainList(data []byte, id string, values panelmodel.DomainListValues) (panelmodel.RuleList, error) {
	var saved panelmodel.RuleList
	if json.Unmarshal(data, &saved) != nil || saved.ID == "" || (id != "" && saved.ID != id) ||
		saved.Name != values.Name || saved.Group != values.Group || saved.Enabled != (values.Group != "") ||
		saved.Masks == nil || !slices.Equal(saved.Masks, values.Masks) {
		return panelmodel.RuleList{}, huma.Error503ServiceUnavailable("Шлюз не подтвердил сохранение доменного списка")
	}
	return saved, nil
}

// deleteInstalledDomainList delegates conditional removal to the fixed privileged helper and awaits its confirmation.
func deleteInstalledDomainList(ctx context.Context, expected panelmodel.RuleList) error {
	return runInstalledChange(ctx, "-delete-domain-list", expected)
}
