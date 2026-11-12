package keeneticphysical

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"unicode"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const (
	maxProviderJSONDepth = 32
	maxProviderJSONNodes = 16384
)

// providerInterface retains only the logical connection fields needed for a trusted display label.
type providerInterface struct {
	description string
	connected   string
	link        string
	defaultGW   bool
}

// defaultProviderName returns the provider description only when RCI reports one connected default-gateway interface.
// It combines the interface tree and route table without inferring a mapping from a physical port ID.
func defaultProviderName(ctx context.Context, client *keeneticrci.Client) (string, error) {
	routes, err := client.Do(ctx, keeneticrci.Operation{
		Name:   "read_default_route",
		Path:   "/rci/show/ip/route",
		Method: keeneticrci.MethodGet,
	}, nil)
	if err != nil {
		return "", err
	}
	interfaces, err := client.Do(ctx, keeneticrci.Operation{
		Name:   "read_interface_labels",
		Path:   "/rci/show/interface",
		Method: keeneticrci.MethodGet,
	}, nil)
	if err != nil {
		return "", err
	}
	defaultIDs := make(map[string]struct{})
	remaining := maxProviderJSONNodes
	if err := collectDefaultRouteInterfaces(routes.Body, 0, &remaining, defaultIDs); err != nil {
		return "", err
	}
	if len(defaultIDs) != 1 {
		return "", nil
	}
	var defaultID string
	for id := range defaultIDs {
		defaultID = id
	}
	providerRecords := make(map[string]providerInterface)
	conflicts := make(map[string]bool)
	remaining = maxProviderJSONNodes
	if err := collectProviderInterfaces(interfaces.Body, 0, &remaining, providerRecords, conflicts); err != nil {
		return "", err
	}
	provider, ok := providerRecords[defaultID]
	if !ok || conflicts[defaultID] || !provider.defaultGW || provider.connected != "yes" || provider.link != "up" {
		return "", nil
	}
	return validProviderName(provider.description), nil
}

// collectDefaultRouteInterfaces finds unique RCI interface IDs for IPv4 default routes in bounded JSON.
func collectDefaultRouteInterfaces(data json.RawMessage, depth int, remaining *int, ids map[string]struct{}) error {
	if depth > maxProviderJSONDepth || remaining == nil || *remaining <= 0 {
		return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
	}
	*remaining--
	var object map[string]json.RawMessage
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
	}
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
		}
		if destination, ok := jsonString(object["destination"]); ok && destination == "0.0.0.0/0" {
			if id, ok := jsonString(object["interface"]); ok && id != "" {
				ids[id] = struct{}{}
			}
		}
		for _, child := range object {
			if err := collectDefaultRouteInterfaces(child, depth+1, remaining, ids); err != nil {
				return err
			}
		}
		return nil
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
		}
		for _, item := range items {
			if err := collectDefaultRouteInterfaces(item, depth+1, remaining, ids); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectProviderInterfaces selects typed Keenetic Ethernet connection records and detects conflicting duplicates.
func collectProviderInterfaces(data json.RawMessage, depth int, remaining *int, providers map[string]providerInterface, conflicts map[string]bool) error {
	if depth > maxProviderJSONDepth || remaining == nil || *remaining <= 0 {
		return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
	}
	*remaining--
	var object map[string]json.RawMessage
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
	}
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
		}
		id, _ := jsonString(object["id"])
		kind, _ := jsonString(object["type"])
		if strings.HasPrefix(id, "GigabitEthernet") && kind == "GigabitEthernet" {
			description, _ := jsonString(object["description"])
			connected, _ := jsonString(object["connected"])
			link, _ := jsonString(object["link"])
			defaultGW, _ := jsonBool(object["defaultgw"])
			current := providerInterface{description: description, connected: connected, link: link, defaultGW: defaultGW}
			if previous, exists := providers[id]; exists && previous != current {
				conflicts[id] = true
			}
			providers[id] = current
		}
		for _, child := range object {
			if err := collectProviderInterfaces(child, depth+1, remaining, providers, conflicts); err != nil {
				return err
			}
		}
		return nil
	}
	if trimmed[0] == '[' {
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return &keeneticrci.Error{Kind: keeneticrci.ErrorSchema}
		}
		for _, item := range items {
			if err := collectProviderInterfaces(item, depth+1, remaining, providers, conflicts); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonString decodes a non-empty JSON string and reports whether the value has the expected type.
func jsonString(data json.RawMessage) (string, bool) {
	var value string
	if len(data) == 0 || json.Unmarshal(data, &value) != nil {
		return "", false
	}
	return value, true
}

// jsonBool decodes a JSON boolean without coercing text or numeric values.
func jsonBool(data json.RawMessage) (bool, bool) {
	var value bool
	if len(data) == 0 || json.Unmarshal(data, &value) != nil {
		return false, false
	}
	return value, true
}

// validProviderName rejects missing, oversized, whitespace-only and control-character labels from RCI.
func validProviderName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return ""
	}
	return name
}
