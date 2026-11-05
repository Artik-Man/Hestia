package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
func runInstalledChange[T panelmodel.RuleList | panelmodel.BindingChange | panelmodel.GroupOrderChange | panelmodel.GroupIdentifier | panelmodel.ExitMoveCommand | panelmodel.GroupDeleteCommand](ctx context.Context, mode string, change T) error {
	return runInstalledHelper(ctx, mode, change, io.Discard)
}

// runInstalledHelper sends one typed request on stdin and captures only the fixed helper's public confirmation.
func runInstalledHelper[T panelmodel.RuleList | panelmodel.DomainListUpdate | panelmodel.DomainListValues | panelmodel.BindingChange | panelmodel.GroupOrderChange | panelmodel.GroupIdentifier | panelmodel.GroupCreateRequest | panelmodel.ExitMoveCommand | panelmodel.GroupDeleteCommand](ctx context.Context, mode string, change T, output io.Writer) error {
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
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		var failure *exec.ExitError
		if errors.As(err, &failure) {
			switch failure.ExitCode() {
			case 44:
				if mode == "-rename-direct" {
					return huma.Error404NotFound("Подключение не найдено")
				}
				if mode == "-delete-group" {
					return huma.Error404NotFound("Группа не найдена")
				}
				if mode == "-move-exit" {
					return huma.Error404NotFound("Подключение или группа не найдены")
				}
				return huma.Error404NotFound("Список или группа не найдены")
			case 42:
				if mode == "-rename-direct" {
					return huma.Error422UnprocessableEntity("Недопустимое название или ID подключения")
				}
				if mode == "-create-domain-list" || mode == "-update-domain-list" || mode == "-delete-domain-list" {
					return huma.Error422UnprocessableEntity("Недопустимые данные доменного списка")
				}
				if mode == "-delete-group" {
					return huma.Error422UnprocessableEntity("Недопустимый ID группы")
				}
				if mode == "-move-exit" {
					return huma.Error422UnprocessableEntity("Недопустимые параметры переноса подключения")
				}
				if mode == "-create-group" || mode == "-rename-group" {
					return huma.Error422UnprocessableEntity("Недопустимое название или ID группы")
				}
				return huma.Error422UnprocessableEntity("Требуется перестановка тех же групп и подключений")
			case 49:
				if mode == "-rename-direct" {
					return huma.Error409Conflict("Переименование доступно для прямого подключения при свободной конфигурации")
				}
				if mode == "-delete-group" {
					return huma.Error409Conflict("Группа содержит подключения, назначена по умолчанию или конфигурация сейчас меняется")
				}
				return huma.Error409Conflict("Конфигурация изменилась или выполняется другая операция")
			}
		}
		log.Printf("routing helper failed: %v", err)
		return huma.Error503ServiceUnavailable("Применение изменения не подтверждено")
	}
	return nil
}
