package panel

import (
	"context"
	"slices"
	"sync"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/quality"
	"github.com/danielgtaylor/huma/v2"
)

type groupQualityOutput struct{ Body quality.GroupSettings }
type groupQualityCheckInput struct {
	GroupID  string `path:"groupID"`
	Protocol string `path:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
	Body     quality.Check
}
type groupQualityCheckPath struct {
	GroupID  string `path:"groupID"`
	Protocol string `path:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
}
type groupQualityWindowInput struct {
	GroupID string `path:"groupID"`
	Body    QualityWindow
}

// registerGroupQuality scopes each check and scoring window edit to an existing topology group.
func registerGroupQuality(api huma.API, snapshot string, files qualityFiles, writes *sync.Mutex) {
	change := func(id string, edit func(*quality.GroupSettings)) (*groupQualityOutput, error) {
		writes.Lock()
		defer writes.Unlock()
		topology, err := readSnapshot(snapshot, false, "")
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать группы подключений")
		}
		if !slices.ContainsFunc(topology.Groups, func(group panelmodel.Group) bool { return group.ID == id }) {
			return nil, huma.Error404NotFound("Группа подключений не найдена")
		}
		settings, err := quality.LoadSettings(files.settings)
		if err != nil {
			return nil, huma.Error503ServiceUnavailable("Не удалось прочитать настройки проверок")
		}
		materializeQualityGroups(&settings, topology.Groups)
		current := settings.ForGroup(id)
		edit(&current)
		settings.Groups[id] = current
		if _, err := files.save(settings); err != nil {
			return nil, err
		}
		return &groupQualityOutput{Body: current}, nil
	}
	huma.Register(api, huma.Operation{OperationID: "putGroupQualityCheck", Tags: []string{"Panel"}, Method: "PUT", Path: "/api/quality/groups/{groupID}/checks/{protocol}", Summary: "Добавить или изменить проверку группы", Description: qualityTargetInputDescription, MaxBodyBytes: 8192, Errors: []int{404, 422, 503}}, func(ctx context.Context, in *groupQualityCheckInput) (*groupQualityOutput, error) {
		if in.Body.Protocol != in.Protocol {
			return nil, huma.Error422UnprocessableEntity("Тип проверки в адресе и настройках должен совпадать")
		}
		if err := in.Body.NormalizeTCPInput(ctx, files.dnsServer); err != nil {
			return nil, huma.Error422UnprocessableEntity(err.Error())
		}
		return change(in.GroupID, func(settings *quality.GroupSettings) {
			for i, check := range settings.Checks {
				if check.Protocol == in.Protocol {
					settings.Checks[i] = in.Body
					return
				}
			}
			settings.Checks = append(settings.Checks, in.Body)
		})
	})
	huma.Register(api, huma.Operation{OperationID: "deleteGroupQualityCheck", Tags: []string{"Panel"}, Method: "DELETE", Path: "/api/quality/groups/{groupID}/checks/{protocol}", Summary: "Удалить проверку группы", Errors: []int{404, 422, 503}}, func(_ context.Context, in *groupQualityCheckPath) (*groupQualityOutput, error) {
		return change(in.GroupID, func(settings *quality.GroupSettings) {
			settings.Checks = slices.DeleteFunc(settings.Checks, func(check quality.Check) bool { return check.Protocol == in.Protocol })
		})
	})
	huma.Register(api, huma.Operation{OperationID: "putGroupQualityWindow", Tags: []string{"Panel"}, Method: "PUT", Path: "/api/quality/groups/{groupID}/window", Summary: "Изменить окно оценки группы", Errors: []int{404, 422, 503}}, func(_ context.Context, in *groupQualityWindowInput) (*groupQualityOutput, error) {
		return change(in.GroupID, func(settings *quality.GroupSettings) { settings.WindowMinutes = in.Body.WindowMinutes })
	})
}

// materializeQualityGroups copies the legacy schedule once and initializes later groups with defaults.
func materializeQualityGroups(settings *quality.Settings, groups []panelmodel.Group) bool {
	changed := false
	original := *settings
	if settings.Groups == nil {
		settings.Groups = make(map[string]quality.GroupSettings)
		changed = true
	}
	for _, group := range groups {
		if _, exists := settings.Groups[group.ID]; !exists {
			settings.Groups[group.ID] = original.ForGroup(group.ID)
			changed = true
		}
	}
	return changed
}

// migrateGroupQuality persists independent group schedules before serving the first grouped report.
func (files qualityFiles) migrateGroupQuality(snapshot string) error {
	if files.settings == "" {
		return nil
	}
	topology, err := readSnapshot(snapshot, false, "")
	if err != nil {
		return err
	}
	settings, err := quality.LoadSettings(files.settings)
	if err != nil {
		return err
	}
	if !materializeQualityGroups(&settings, topology.Groups) {
		return nil
	}
	_, err = files.save(settings)
	return err
}
