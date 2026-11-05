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
	"regexp"

	"github.com/Artik-Man/Hestia/internal/awg"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

const maxAWGRequestBytes = 40 * 1024

var awgIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// awgWriter exposes privileged, secret-safe AWG operations to the local panel.
type awgWriter interface {
	Check(context.Context, string) (panelmodel.AWGCheckResult, error)
	Create(context.Context, panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error)
	Update(context.Context, panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error)
	List(context.Context) ([]panelmodel.AWGConnection, error)
	Underlays(context.Context) ([]panelmodel.AWGUnderlayCandidate, error)
	ReadProfile(context.Context, string) (panelmodel.AWGConnectionProfile, error)
	Delete(context.Context, string) error
}

type awgCheckInput struct{ Body panelmodel.AWGCheckRequest }
type awgCheckOutput struct{ Body panelmodel.AWGCheckResult }
type awgSaveInput struct{ Body panelmodel.AWGSaveRequest }
type awgSaveOutput struct{ Body panelmodel.AWGConnection }
type awgUpdateInput struct {
	ID   string `path:"id" minLength:"1"`
	Body panelmodel.AWGUpdateRequest
}
type awgUpdateOutput struct{ Body panelmodel.AWGConnection }
type awgListOutput struct {
	Body []panelmodel.AWGConnection `json:"connections" nullable:"false"`
}
type awgUnderlaysOutput struct {
	Body []panelmodel.AWGUnderlayCandidate `nullable:"false"`
}
type awgProfileOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         panelmodel.AWGConnectionProfile
}
type awgIDInput struct {
	ID string `path:"id" minLength:"1"`
}

// registerAWG publishes profile check and CRUD routes; nil writers fail closed with 503.
func registerAWG(api huma.API, write awgWriter) {
	huma.Register(api, huma.Operation{
		OperationID: "checkAWGProfile", Tags: []string{"Panel"}, Method: http.MethodPost, Path: "/api/awg/check",
		Summary: "Проверить временный профиль AmneziaWG без сохранения", MaxBodyBytes: maxAWGRequestBytes, SkipValidateBody: true,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *awgCheckInput) (*awgCheckOutput, error) {
		if len(in.Body.Profile) == 0 || len(in.Body.Profile) > maxAWGRequestBytes {
			return nil, huma.Error422UnprocessableEntity("Размер профиля AmneziaWG недопустим")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Проверка AmneziaWG не включена")
		}
		result, err := write.Check(ctx, in.Body.Profile)
		if err != nil {
			return nil, mapAWGError(err)
		}
		return &awgCheckOutput{Body: result}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "createAWGConnection", Tags: []string{"Panel"}, Method: http.MethodPost, Path: "/api/awg",
		Summary: "Сохранить профиль AmneziaWG и назначение группе", MaxBodyBytes: maxAWGRequestBytes, SkipValidateBody: true,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusConflict, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *awgSaveInput) (*awgSaveOutput, error) {
		if err := validateAWGSave(in.Body, false); err != nil {
			return nil, huma.Error422UnprocessableEntity("Некорректные данные подключения AmneziaWG")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Управление AmneziaWG не включено")
		}
		connection, err := write.Create(ctx, in.Body)
		if err != nil {
			return nil, mapAWGError(err)
		}
		return &awgSaveOutput{Body: connection}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "listAWGConnections", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/awg",
		Summary: "Прочитать подключения AmneziaWG без секретных данных", Errors: []int{http.StatusServiceUnavailable},
	}, func(ctx context.Context, _ *struct{}) (*awgListOutput, error) {
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Управление AmneziaWG не включено")
		}
		connections, err := write.List(ctx)
		if err != nil {
			return nil, mapAWGError(err)
		}
		return &awgListOutput{Body: connections}, nil
	})
	huma.Register(api, huma.Operation{OperationID: "listAWGUnderlays", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/awg-underlays", Summary: "Получить подключения для транспорта WireGuard", Errors: []int{http.StatusConflict, http.StatusServiceUnavailable}},
		func(ctx context.Context, _ *struct{}) (*awgUnderlaysOutput, error) {
			if write == nil {
				return nil, huma.Error503ServiceUnavailable("Управление WireGuard не включено")
			}
			result, err := write.Underlays(ctx)
			if err != nil {
				return nil, mapAWGError(err)
			}
			return &awgUnderlaysOutput{Body: result}, nil
		})
	huma.Register(api, huma.Operation{
		OperationID: "getAWGConnectionProfile", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/awg/{id}",
		Summary: "Открыть один сохранённый профиль WireGuard для редактирования, включая ключи",
		Errors:  []int{http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *awgIDInput) (*awgProfileOutput, error) {
		if !awgIDPattern.MatchString(in.ID) {
			return nil, huma.Error404NotFound("Подключение WireGuard не найдено")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Управление WireGuard не включено")
		}
		profile, err := write.ReadProfile(ctx, in.ID)
		if err != nil {
			return nil, mapAWGError(err)
		}
		if profile.ID != in.ID || profile.Priority < 1 || validateAWGSave(panelmodel.AWGSaveRequest{ID: profile.ID, Group: profile.Group, Priority: panelmodel.AWGPriority(profile.Priority), Underlays: profile.Underlays, Profile: profile.Profile}, false) != nil {
			return nil, mapAWGError(errors.New("invalid profile response"))
		}
		parsed, err := awg.Parse([]byte(profile.Profile))
		if err != nil || profile.Profile != string(parsed.SecretConfig) {
			return nil, mapAWGError(errors.New("unexpected profile format"))
		}
		return &awgProfileOutput{CacheControl: "no-store", Body: profile}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "updateAWGConnection", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/awg/{id}",
		Summary: "Обновить сохранённое подключение AmneziaWG", MaxBodyBytes: maxAWGRequestBytes, SkipValidateBody: true,
		Errors: []int{http.StatusNotFound, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *awgUpdateInput) (*awgUpdateOutput, error) {
		request := panelmodel.AWGSaveRequest{Underlays: in.Body.Underlays, ID: in.ID, Group: string(in.Body.Group), Priority: in.Body.Priority, Profile: in.Body.Profile}
		if !awgIDPattern.MatchString(in.ID) {
			return nil, huma.Error404NotFound("Подключение AmneziaWG не найдено")
		}
		if err := validateAWGSave(request, true); err != nil {
			return nil, huma.Error422UnprocessableEntity("Некорректные данные подключения AmneziaWG")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Управление AmneziaWG не включено")
		}
		connection, err := write.Update(ctx, request)
		if err != nil {
			return nil, mapAWGError(err)
		}
		return &awgUpdateOutput{Body: connection}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "deleteAWGConnection", Tags: []string{"Panel"}, Method: http.MethodDelete, Path: "/api/awg/{id}",
		Summary: "Удалить подключение AmneziaWG", Errors: []int{http.StatusNotFound, http.StatusConflict, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *awgIDInput) (*struct{}, error) {
		if !awgIDPattern.MatchString(in.ID) {
			return nil, huma.Error404NotFound("Подключение AmneziaWG не найдено")
		}
		if write == nil {
			return nil, huma.Error503ServiceUnavailable("Управление AmneziaWG не включено")
		}
		if err := write.Delete(ctx, in.ID); err != nil {
			return nil, mapAWGError(err)
		}
		return &struct{}{}, nil
	})
}

// awgHTTPFailure stores a sanitized status class returned by the fixed privileged helper.
type awgHTTPFailure struct {
	status int
}

// Error returns a generic message that contains no helper output or profile contents.
func (e awgHTTPFailure) Error() string { return "AWG helper operation failed" }

// mapAWGError converts a known helper status to a stable Huma response and hides all other details.
func mapAWGError(err error) error {
	var failure awgHTTPFailure
	if errors.As(err, &failure) {
		switch failure.status {
		case http.StatusUnprocessableEntity:
			return huma.Error422UnprocessableEntity("Некорректный профиль или назначение группы AmneziaWG")
		case http.StatusNotFound:
			return huma.Error404NotFound("Подключение AmneziaWG не найдено")
		case http.StatusConflict:
			return huma.Error409Conflict("Конфигурация AmneziaWG изменилась или занята")
		}
	}
	return huma.Error503ServiceUnavailable("Операция AmneziaWG не подтверждена")
}

// validateAWGSave rejects invalid IDs, group assignment, priority, and oversized private profile content.
func validateAWGSave(request panelmodel.AWGSaveRequest, update bool) error {
	if !awgIDPattern.MatchString(request.ID) || !awg.ValidUnderlays(request.ID, request.Underlays) || ((!update || request.Group != "") && !awgIDPattern.MatchString(request.Group)) || request.Priority < 0 || len(request.Profile) == 0 || len(request.Profile) > maxAWGRequestBytes {
		return errors.New("invalid AWG save request")
	}
	return nil
}

// installedAWGWriter invokes fixed root-helper modes; only ReadProfile returns saved secrets.
type installedAWGWriter struct{}

// Check submits a candidate to the root helper and returns only an explicit successful runtime result.
func (installedAWGWriter) Check(ctx context.Context, profile string) (panelmodel.AWGCheckResult, error) {
	var result panelmodel.AWGCheckResult
	return result, runAWGHelper(ctx, "-awg-check", panelmodel.AWGCheckRequest{Profile: profile}, &result)
}

// Create submits a new typed profile to the root helper and returns its public metadata.
func (installedAWGWriter) Create(ctx context.Context, request panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error) {
	var result panelmodel.AWGConnection
	return result, runAWGHelper(ctx, "-awg-create", request, &result)
}

// Update replaces an existing typed profile through the root helper and returns public metadata.
func (installedAWGWriter) Update(ctx context.Context, request panelmodel.AWGSaveRequest) (panelmodel.AWGConnection, error) {
	var result panelmodel.AWGConnection
	return result, runAWGHelper(ctx, "-awg-update", request, &result)
}

// List retrieves only public connector metadata from the root helper.
func (installedAWGWriter) List(ctx context.Context) ([]panelmodel.AWGConnection, error) {
	var result []panelmodel.AWGConnection
	return result, runAWGHelper(ctx, "-awg-list", struct{}{}, &result)
}

// ReadProfile requests one full secret profile by ID over the helper's private stdout pipe.
func (installedAWGWriter) ReadProfile(ctx context.Context, id string) (panelmodel.AWGConnectionProfile, error) {
	var result panelmodel.AWGConnectionProfile
	err := runAWGHelper(ctx, "-awg-read", panelmodel.AWGIDRequest{ID: id}, &result)
	return result, err
}

// Delete asks the root helper to remove one fixed-ID connection and its private profile.
func (installedAWGWriter) Delete(ctx context.Context, id string) error {
	return runAWGHelper(ctx, "-awg-delete", panelmodel.AWGIDRequest{ID: id}, nil)
}

// runAWGHelper passes bounded typed input through stdin to one fixed helper mode without exposing it in argv or logs.
func runAWGHelper(ctx context.Context, mode string, input any, output any) error {
	data, err := json.Marshal(input)
	if err != nil || len(data) > maxAWGRequestBytes {
		return errors.New("invalid AWG request")
	}
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", "/usr/local/bin/hestia", mode)
	command.Stdin = bytes.NewReader(data)
	command.Stderr = os.Stderr
	response, err := command.Output()
	if err != nil {
		log.Printf("AWG helper operation failed: %s", mode)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			switch exit.ExitCode() {
			case 42:
				return awgHTTPFailure{status: http.StatusUnprocessableEntity}
			case 44:
				return awgHTTPFailure{status: http.StatusNotFound}
			case 49:
				return awgHTTPFailure{status: http.StatusConflict}
			}
		}
		return awgHTTPFailure{status: http.StatusServiceUnavailable}
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(response, output); err != nil {
		return errors.New("invalid AWG helper response")
	}
	return nil
}

// Underlays retrieves eligible public exit identities without reading any secret configuration.
func (installedAWGWriter) Underlays(ctx context.Context) ([]panelmodel.AWGUnderlayCandidate, error) {
	var result []panelmodel.AWGUnderlayCandidate
	err := runAWGHelper(ctx, "-awg-underlays", struct{}{}, &result)
	return result, err
}
