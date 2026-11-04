package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

// bindingWriter returns only after the controller confirms application or rejects the change.
type bindingWriter func(context.Context, panelmodel.BindingChange) error

type bindingInput struct {
	Body panelmodel.BindingChange
}

type bindingOutput struct {
	Body panelmodel.AppliedBinding
}

// registerBinding exposes the compare-and-set operation even on a read-only panel,
// which responds with 503 and never calls a privileged helper.
func registerBinding(api huma.API, write bindingWriter) {
	huma.Register(api, huma.Operation{
		OperationID: "applyListBinding", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/list-binding",
		Summary: "Применить привязку доменного списка", MaxBodyBytes: 8192,
		Errors: []int{http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *bindingInput) (*bindingOutput, error) {
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Изменение привязок не включено")
		}
		if err := write(ctx, in.Body); err != nil {
			return nil, err
		}
		return &bindingOutput{Body: panelmodel.AppliedBinding{ListID: in.Body.ListID, Group: in.Body.Group}}, nil
	})
}

// applyInstalledBinding invokes only the installed helper with a fixed argument list.
// User-controlled identifiers travel as JSON on stdin, never as command arguments.
func applyInstalledBinding(ctx context.Context, change panelmodel.BindingChange) error {
	return runInstalledChange(ctx, "-apply-binding", change)
}

// runInstalledChange passes a typed payload through stdin to one caller-selected, fixed helper mode.
func runInstalledChange[T panelmodel.BindingChange | panelmodel.GroupOrderChange](ctx context.Context, mode string, change T) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(change)
	if err != nil {
		return err
	}
	// The helper owns its deadline and rollback. A disconnected browser must not kill it mid-transaction.
	cmd := exec.Command("/usr/bin/sudo", "-n", "--", "/usr/local/bin/hestia", mode)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			switch failure.ExitCode() {
			case 44:
				return huma.Error404NotFound("Список или группа не найдены")
			case 42:
				return huma.Error422UnprocessableEntity("Требуется перестановка тех же групп и подключений")
			case 49:
				return huma.Error409Conflict("Конфигурация изменилась или выполняется другая операция")
			}
		}
		log.Printf("routing helper failed: %v", err)
		return huma.Error503ServiceUnavailable("Применение изменения не подтверждено")
	}
	return nil
}
