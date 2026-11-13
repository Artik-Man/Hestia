package panel

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/danielgtaylor/huma/v2"
)

// qualityFiles identifies panel-owned settings and the gateway worker's atomically published report.
type qualityFiles struct {
	settings, report string
	dnsServer        string // Empty selects the system nameserver for save-time TCP hostname resolution.
}

const qualityTargetInputDescription = "Цель TCP принимает IP-адрес или доменное имя с необязательным портом (по умолчанию 443). Сервер один раз запрашивает A-запись каждого имени, выбирает первый допустимый публичный IPv4 и возвращает сохранённые цели в формате IP:порт. Ошибка разрешения отклоняет весь запрос с HTTP 422."

type qualityReportOutput struct{ Body panelmodel.QualityReport }
type qualitySettingsInput struct{ Body quality.Settings }
type qualitySettingsOutput struct{ Body quality.Settings }

type qualityCheckPath struct {
	Protocol string `path:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
}
type qualityCheckInput struct {
	Protocol string `path:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
	Body     quality.Check
}

// QualityWindow sets the common measurement window independently of individual checks.
type QualityWindow struct {
	WindowMinutes int `json:"windowMinutes" minimum:"1" maximum:"1440"`
}
type qualityWindowInput struct{ Body QualityWindow }

// save validates a complete configuration and atomically publishes it for the running gateway.
func (files qualityFiles) save(settings quality.Settings) (*qualitySettingsOutput, error) {
	if err := quality.ValidateSettings(settings); err != nil {
		return nil, huma.Error422UnprocessableEntity(err.Error())
	}
	if files.settings == "" {
		return nil, huma.Error503ServiceUnavailable("Файл настроек проверок не настроен")
	}
	if err := quality.SaveSettings(files.settings, settings); err != nil {
		log.Printf("save quality settings: %v", err)
		return nil, huma.Error503ServiceUnavailable("Не удалось сохранить настройки проверок")
	}
	return &qualitySettingsOutput{Body: settings}, nil
}

// registerQuality exposes the worker's ranking and validates complete setting replacements before persistence.
func registerQuality(api huma.API, snapshot string, files qualityFiles) {
	var writes sync.Mutex
	registerGroupQuality(api, snapshot, files, &writes)
	change := func(edit func(*quality.Settings)) (*qualitySettingsOutput, error) {
		writes.Lock()
		defer writes.Unlock()
		settings, err := quality.LoadSettings(files.settings)
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать настройки проверок")
		}
		edit(&settings)
		return files.save(settings)
	}
	huma.Register(api, huma.Operation{
		OperationID: "getQuality", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/quality",
		Summary: "Прочитать настройки проверок и текущий порядок выходов всех групп", Errors: []int{http.StatusServiceUnavailable},
	}, func(_ context.Context, _ *struct{}) (*qualityReportOutput, error) {
		writes.Lock()
		defer writes.Unlock()
		if err := files.migrateGroupQuality(snapshot); err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось подготовить настройки групп")
		}
		report, err := files.readReport(snapshot)
		if err != nil {
			log.Printf("quality report: %v", err)
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать сведения о качестве связи")
		}
		return &qualityReportOutput{Body: report}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "resetQualityResults", Tags: []string{"Panel"}, Method: http.MethodPost, Path: "/api/quality/reset",
		Summary: "Сбросить накопленные результаты проверок связи", DefaultStatus: http.StatusNoContent,
		Errors: []int{http.StatusServiceUnavailable},
	}, func(_ context.Context, _ *struct{}) (*struct{}, error) {
		if files.settings == "" {
			return nil, huma.Error503ServiceUnavailable("Файл настроек проверок не настроен")
		}
		if err := writeQualityReset(files.settings+".reset", time.Now().UnixNano()); err != nil {
			log.Printf("reset quality results: %v", err)
			return nil, huma.Error503ServiceUnavailable("Не удалось сбросить результаты проверок")
		}
		return &struct{}{}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "updateQualitySettings", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/quality/settings",
		Summary: "Сохранить общие для всех выходов параметры проверок связи", Description: qualityTargetInputDescription, MaxBodyBytes: 8192,
		Errors: []int{http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *qualitySettingsInput) (*qualitySettingsOutput, error) {
		tcp := -1
		for i, check := range in.Body.Checks {
			if check.Protocol == quality.TCP {
				if tcp >= 0 {
					return nil, huma.Error422UnprocessableEntity("Допустима одна проверка TCP")
				}
				tcp = i
			}
		}
		if tcp >= 0 {
			if err := in.Body.Checks[tcp].NormalizeTCPInput(ctx, files.dnsServer); err != nil {
				return nil, huma.Error422UnprocessableEntity(err.Error())
			}
		}
		writes.Lock()
		defer writes.Unlock()
		current, err := quality.LoadSettings(files.settings)
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать настройки проверок")
		}
		// Legacy clients may replace the migration seed, but cannot replace group schedules.
		in.Body.Groups = current.Groups
		return files.save(in.Body)
	})
	huma.Register(api, huma.Operation{OperationID: "putQualityCheck", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/quality/checks/{protocol}", Summary: "Добавить или изменить одну проверку связи", Description: qualityTargetInputDescription, MaxBodyBytes: 8192, Errors: []int{422, 503}}, func(ctx context.Context, in *qualityCheckInput) (*qualitySettingsOutput, error) {
		if in.Body.Protocol != in.Protocol {
			return nil, huma.Error422UnprocessableEntity("Тип проверки в адресе и настройках должен совпадать")
		}
		if err := in.Body.NormalizeTCPInput(ctx, files.dnsServer); err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		return change(func(settings *quality.Settings) {
			for i, check := range settings.Checks {
				if check.Protocol == in.Protocol {
					settings.Checks[i] = in.Body
					return
				}
			}
			settings.Checks = append(settings.Checks, in.Body)
		})
	})
	huma.Register(api, huma.Operation{OperationID: "deleteQualityCheck", Tags: []string{"Panel"}, Method: http.MethodDelete, Path: "/api/quality/checks/{protocol}", Summary: "Удалить одну проверку связи", Errors: []int{422, 503}}, func(_ context.Context, in *qualityCheckPath) (*qualitySettingsOutput, error) {
		return change(func(settings *quality.Settings) {
			settings.Checks = slices.DeleteFunc(settings.Checks, func(check quality.Check) bool { return check.Protocol == in.Protocol })
		})
	})
	huma.Register(api, huma.Operation{OperationID: "putQualityWindow", Tags: []string{"Panel"}, Method: http.MethodPut, Path: "/api/quality/window", Summary: "Изменить общее окно оценки", Errors: []int{422, 503}}, func(_ context.Context, in *qualityWindowInput) (*qualitySettingsOutput, error) {
		return change(func(settings *quality.Settings) { settings.WindowMinutes = in.Body.WindowMinutes })
	})
}

// writeQualityReset atomically publishes a timestamped reset request for the probe worker.
func writeQualityReset(path string, timestamp int64) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".quality-reset-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.WriteString(strconv.FormatInt(timestamp, 10)); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// readReport returns a matching recent worker report, or topology with unknown scores until one arrives.
func (files qualityFiles) readReport(snapshot string) (panelmodel.QualityReport, error) {
	settings := quality.DefaultSettings()
	if files.settings != "" {
		stored, err := quality.LoadSettings(files.settings)
		if err != nil {
			return panelmodel.QualityReport{}, err
		}
		settings = stored
	}
	topology, err := readSnapshot(snapshot, false, "")
	if err != nil {
		return panelmodel.QualityReport{}, err
	}
	report, err := readFreshQualityReport(files.report, snapshot, topology.Groups)
	if err != nil {
		return panelmodel.QualityReport{}, err
	}
	if report != nil && files.settings != "" {
		reset, readErr := os.ReadFile(files.settings + ".reset")
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return panelmodel.QualityReport{}, readErr
		}
		if readErr == nil {
			resetAt, parseErr := strconv.ParseInt(string(reset), 10, 64)
			capturedAt, timeErr := time.Parse(time.RFC3339Nano, report.CapturedAt)
			if parseErr != nil || timeErr != nil {
				return panelmodel.QualityReport{}, errors.Join(parseErr, timeErr)
			}
			if capturedAt.UnixNano() <= resetAt {
				report = nil
			}
		}
	}
	if report != nil && reflect.DeepEqual(settings, report.Settings) {
		return *report, nil
	}
	view := panelmodel.QualityReport{Settings: settings, Groups: make([]panelmodel.QualityGroup, 0, len(topology.Groups))}
	for _, group := range topology.Groups {
		row := panelmodel.QualityGroup{ID: group.ID, Name: group.Name, Settings: settings.ForGroup(group.ID), Connections: make([]panelmodel.QualityConnection, 0, len(group.Exits))}
		for _, exit := range group.Exits {
			row.Connections = append(row.Connections, panelmodel.QualityConnection{ID: exit.ID, Available: exit.Available, Result: emptyQualityResult(quality.Settings{WindowMinutes: row.Settings.WindowMinutes, Checks: row.Settings.Checks})})
		}
		view.Groups = append(view.Groups, row)
	}
	return view, nil
}

// readFreshQualityReport accepts a recent report matching the current topology and published after its snapshot.
func readFreshQualityReport(path, snapshot string, groups []panelmodel.Group) (*panelmodel.QualityReport, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var report panelmodel.QualityReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	captured, err := time.Parse(time.RFC3339Nano, report.CapturedAt)
	age := time.Since(captured)
	if err != nil || age < 0 || age > time.Minute || !matchesQualityGroups(report.Groups, groups) {
		return nil, nil
	}
	source, err := os.Stat(snapshot)
	if err != nil {
		return nil, err
	}
	if captured.Before(source.ModTime()) {
		return nil, nil
	}
	return &report, nil
}

// matchesQualityGroups rejects worker data from a previous topology while permitting ranked exit order.
func matchesQualityGroups(report []panelmodel.QualityGroup, groups []panelmodel.Group) bool {
	if len(report) != len(groups) {
		return false
	}
	for i, group := range groups {
		ranked := report[i]
		if ranked.ID != group.ID || ranked.Name != group.Name || len(ranked.Connections) != len(group.Exits) {
			return false
		}
		ids := make(map[string]bool, len(group.Exits))
		for _, exit := range group.Exits {
			ids[exit.ID] = true
		}
		for _, row := range ranked.Connections {
			if !ids[row.ID] {
				return false
			}
			delete(ids, row.ID)
		}
	}
	return true
}

// emptyQualityResult provides zero sample counts and unavailable scores for all configured checks and targets.
func emptyQualityResult(settings quality.Settings) quality.Result {
	result := quality.Result{Checks: make([]quality.CheckResult, 0, len(settings.Checks))}
	for _, check := range settings.Checks {
		row := quality.CheckResult{Protocol: check.Protocol, Targets: make([]quality.TargetResult, 0, len(check.Targets))}
		for _, target := range check.Targets {
			row.Targets = append(row.Targets, quality.TargetResult{Target: target})
		}
		result.Checks = append(result.Checks, row)
	}
	return result
}
