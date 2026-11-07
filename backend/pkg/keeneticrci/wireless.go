package keeneticrci

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxWirelessJSONDepth = 32
	maxWirelessJSONNodes = 16384
)

var (
	wispIDPattern = regexp.MustCompile(`^WifiMaster[0-9]+/WifiStation[0-9]+$`)
	errNoWISP     = &Error{Kind: ErrorSchema}
	errBadWISP    = &Error{Kind: ErrorSchema}
)

// WirelessLinkState is the observed link value for a Keenetic WISP station.
type WirelessLinkState string

const (
	// WirelessLinkUnknown means Keenetic did not provide a recognized link value.
	WirelessLinkUnknown WirelessLinkState = "unknown"
	// WirelessLinkDown means the WISP station reports no active link.
	WirelessLinkDown WirelessLinkState = "down"
	// WirelessLinkUp means the WISP station reports an active link.
	WirelessLinkUp WirelessLinkState = "up"
)

// WirelessInterfaceState is the observed administrative state of a Keenetic WISP station.
type WirelessInterfaceState string

const (
	// WirelessStateUnknown means Keenetic did not provide a recognized administrative state.
	WirelessStateUnknown WirelessInterfaceState = "unknown"
	// WirelessStateDown means the WISP station is administratively down.
	WirelessStateDown WirelessInterfaceState = "down"
	// WirelessStateUp means the WISP station is administratively up.
	WirelessStateUp WirelessInterfaceState = "up"
)

// WISPInterface contains redacted operational status for one wireless station interface.
// It deliberately excludes SSID, description, credentials, addresses, and radio scan results.
type WISPInterface struct {
	ID             string                 `json:"id"`
	Link           WirelessLinkState      `json:"link"`
	State          WirelessInterfaceState `json:"state"`
	Connected      *bool                  `json:"connected,omitempty"`
	DefaultGateway *bool                  `json:"defaultGateway,omitempty"`
	Priority       *uint32                `json:"priority,omitempty"`
}

// WISPInventory is a typed, redacted snapshot of configured wireless station interfaces.
type WISPInventory struct {
	Interfaces []WISPInterface
	Response   ResponseMetadata
}

// WISPConnector reads wireless station status without exposing profile identifiers or secrets.
type WISPConnector struct {
	client *Client
}

// NewWISPConnector creates a read-only WISP connector using the supplied authenticated client.
func NewWISPConnector(client *Client) (*WISPConnector, error) {
	if client == nil {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	return &WISPConnector{client: client}, nil
}

// Read returns only bounded operational fields for wireless station records from show/interface.
func (c *WISPConnector) Read(ctx context.Context) (WISPInventory, error) {
	response, err := c.client.Do(ctx, Operation{
		Name:   "show_wireless_interfaces",
		Path:   "/rci/show/interface",
		Method: MethodGet,
	}, nil)
	if err != nil {
		return WISPInventory{}, err
	}
	interfaces := make(map[string]WISPInterface)
	remainingNodes := maxWirelessJSONNodes
	if err := collectWISPInterfaces(response.Body, interfaces, 0, &remainingNodes); err != nil {
		return WISPInventory{}, err
	}
	if len(interfaces) == 0 {
		return WISPInventory{}, errNoWISP
	}
	ids := make([]string, 0, len(interfaces))
	for id := range interfaces {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]WISPInterface, 0, len(ids))
	for _, id := range ids {
		result = append(result, interfaces[id])
	}
	return WISPInventory{
		Interfaces: result,
		Response: ResponseMetadata{
			Status:      response.Status,
			ContentType: response.ContentType,
			BodyBytes:   response.BodyBytes,
			BodySHA256:  response.BodySHA256,
		},
	}, nil
}

// collectWISPInterfaces walks bounded RCI JSON and retains only identified station records.
func collectWISPInterfaces(data json.RawMessage, interfaces map[string]WISPInterface, depth int, remainingNodes *int) error {
	if depth > maxWirelessJSONDepth || remainingNodes == nil || *remainingNodes <= 0 {
		return errBadWISP
	}
	*remainingNodes = *remainingNodes - 1
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return errBadWISP
	}
	switch trimmed[0] {
	case '{':
		var members map[string]json.RawMessage
		if err := json.Unmarshal(data, &members); err != nil {
			return errBadWISP
		}
		if rawID, ok := members["id"]; ok {
			var id string
			if json.Unmarshal(rawID, &id) == nil && wispIDPattern.MatchString(id) {
				station, err := parseWISPInterface(id, members)
				if err != nil {
					return err
				}
				if existing, found := interfaces[id]; found {
					merged, err := mergeWISPInterface(existing, station)
					if err != nil {
						return err
					}
					interfaces[id] = merged
				} else {
					interfaces[id] = station
				}
			}
		}
		for _, child := range members {
			if err := collectWISPInterfaces(child, interfaces, depth+1, remainingNodes); err != nil {
				return err
			}
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return errBadWISP
		}
		for _, item := range items {
			if err := collectWISPInterfaces(item, interfaces, depth+1, remainingNodes); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseWISPInterface validates one station record and ignores every field outside its status allowlist.
func parseWISPInterface(id string, members map[string]json.RawMessage) (WISPInterface, error) {
	var kind string
	if json.Unmarshal(members["type"], &kind) != nil || kind != "wifistation" {
		return WISPInterface{}, errBadWISP
	}
	station := WISPInterface{ID: id, Link: WirelessLinkUnknown, State: WirelessStateUnknown}
	if rawLink, ok := members["link"]; ok {
		var link string
		if json.Unmarshal(rawLink, &link) != nil {
			return WISPInterface{}, errBadWISP
		}
		switch link {
		case "up":
			station.Link = WirelessLinkUp
		case "down":
			station.Link = WirelessLinkDown
		default:
			return WISPInterface{}, errBadWISP
		}
	}
	if rawState, ok := members["state"]; ok {
		var state string
		if json.Unmarshal(rawState, &state) != nil {
			return WISPInterface{}, errBadWISP
		}
		switch state {
		case "up":
			station.State = WirelessStateUp
		case "down":
			station.State = WirelessStateDown
		default:
			return WISPInterface{}, errBadWISP
		}
	}
	if rawConnected, ok := members["connected"]; ok {
		var connected bool
		if json.Unmarshal(rawConnected, &connected) != nil {
			return WISPInterface{}, errBadWISP
		}
		station.Connected = &connected
	}
	if rawGateway, ok := members["defaultgw"]; ok {
		var gateway bool
		if json.Unmarshal(rawGateway, &gateway) != nil {
			return WISPInterface{}, errBadWISP
		}
		station.DefaultGateway = &gateway
	}
	if rawPriority, ok := members["priority"]; ok {
		priorityText := string(bytes.TrimSpace(rawPriority))
		if strings.HasPrefix(priorityText, "\"") {
			if json.Unmarshal(rawPriority, &priorityText) != nil {
				return WISPInterface{}, errBadWISP
			}
		}
		value, err := strconv.ParseUint(priorityText, 10, 32)
		if err != nil {
			return WISPInterface{}, errBadWISP
		}
		priority := uint32(value)
		station.Priority = &priority
	}
	return station, nil
}

// mergeWISPInterface combines repeated station records and rejects contradictory observations.
func mergeWISPInterface(left, right WISPInterface) (WISPInterface, error) {
	if left.ID != right.ID || left.Link != right.Link || left.State != right.State {
		return WISPInterface{}, errBadWISP
	}
	merged := left
	if merged.Connected == nil {
		merged.Connected = right.Connected
	} else if right.Connected != nil && *merged.Connected != *right.Connected {
		return WISPInterface{}, errBadWISP
	}
	if merged.DefaultGateway == nil {
		merged.DefaultGateway = right.DefaultGateway
	} else if right.DefaultGateway != nil && *merged.DefaultGateway != *right.DefaultGateway {
		return WISPInterface{}, errBadWISP
	}
	if merged.Priority == nil {
		merged.Priority = right.Priority
	} else if right.Priority != nil && *merged.Priority != *right.Priority {
		return WISPInterface{}, errBadWISP
	}
	return merged, nil
}
