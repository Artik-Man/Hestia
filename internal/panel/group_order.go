package panel

import (
	"context"
	"net/http"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// orderWriter returns success only after confirming the requested topology is active.
type orderWriter func(context.Context, panelmodel.GroupOrderChange) error

// panelWrites holds independently enabled privileged operations.
type panelWrites struct {
	dnsPolicyPath    string
	dnsReportPath    string
	quality          qualityFiles
	physical         physicalHelper
	deleteDomainList domainListDeleter
	createDomainList domainListCreator
	updateDomainList domainListUpdater
	binding          bindingWriter
	order            orderWriter
	createGroup      groupCreator
	renameDirect     groupRenamer
	renameGroup      groupRenamer
	deleteGroup      groupDeleter
	moveExit         exitMover
	awg              awgWriter
}

type orderInput struct{ Body panelmodel.GroupOrderChange }
type orderOutput struct{ Body panelmodel.AppliedOrder }

// registerOrder publishes the full-topology compare-and-set operation and bounds the size of its request.
func registerOrder(api huma.API, write orderWriter) {
	huma.Register(api, huma.Operation{
		OperationID: "applyGroupOrder", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/group-order",
		Summary: "Применить порядок групп и подключений", MaxBodyBytes: 65536, SkipValidateBody: true,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *orderInput) (*orderOutput, error) {
		// Stop after the first malformed group instead of building one validation error per element.
		if err := binding.ValidateOrder(in.Body); err != nil {
			return nil, huma.Error422UnprocessableEntity("Некорректный порядок групп или выходов")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Изменение порядка не включено")
		}
		if err := write(ctx, in.Body); err != nil {
			return nil, err
		}
		return &orderOutput{Body: panelmodel.AppliedOrder{Groups: in.Body.Groups}}, nil
	})
}

// applyInstalledOrder invokes the helper mode restricted to reordering the installed topology.
func applyInstalledOrder(ctx context.Context, change panelmodel.GroupOrderChange) error {
	return runInstalledChange(ctx, "-apply-group-order", change)
}
