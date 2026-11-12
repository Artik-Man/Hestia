package keeneticrci

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	portIDPattern = regexp.MustCompile(`^GigabitEthernet[0-9]+/[0-9]+$`)
	errNoPorts    = &Error{Kind: ErrorSchema}
	errBadPort    = &Error{Kind: ErrorSchema}
)

// LinkState is the enumerated physical link state returned by Keenetic RCI.
type LinkState string

const (
	// LinkDown means the port has no active link in the observed snapshot.
	LinkDown LinkState = "down"
	// LinkUp means the port reports an active physical link.
	LinkUp LinkState = "up"
)

// Duplex is the enumerated Ethernet duplex mode reported for a linked port.
type Duplex string

const (
	// DuplexHalf is half-duplex Ethernet.
	DuplexHalf Duplex = "half"
	// DuplexFull is full-duplex Ethernet.
	DuplexFull Duplex = "full"
)

// EthernetPort is a validated physical Ethernet port inventory record.
type EthernetPort struct {
	ID        string    `json:"id"`
	Link      LinkState `json:"link"`
	SpeedMbps *uint32   `json:"speedMbps,omitempty"`
	Duplex    *Duplex   `json:"duplex,omitempty"`
}

// ResponseMetadata retains safe HTTP evidence without exposing the RCI JSON body.
type ResponseMetadata struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	BodyBytes   int64  `json:"body_bytes"`
	BodySHA256  string `json:"body_sha256"`
}

// EthernetInventory is a typed port snapshot and its redacted transport metadata.
type EthernetInventory struct {
	Ports    []EthernetPort
	Response ResponseMetadata
}

// EthernetConnector reads physical port metadata through the authenticated RCI client.
type EthernetConnector struct {
	client *Client
}

// NewEthernetConnector creates a read-only Ethernet connector using the supplied RCI client.
func NewEthernetConnector(client *Client) (*EthernetConnector, error) {
	if client == nil {
		return nil, &Error{Kind: ErrorInvalidConfig}
	}
	return &EthernetConnector{client: client}, nil
}

// List returns unique physical Ethernet ports from the authorized show/interface RCI response.
func (c *EthernetConnector) List(ctx context.Context) ([]EthernetPort, error) {
	inventory, err := c.Read(ctx)
	if err != nil {
		return nil, err
	}
	return inventory.Ports, nil
}

// Read returns a typed port snapshot and safe response metadata from show/interface.
func (c *EthernetConnector) Read(ctx context.Context) (EthernetInventory, error) {
	response, err := c.client.Do(ctx, Operation{
		Name:   "show_interfaces",
		Path:   "/rci/show/interface",
		Method: MethodGet,
	}, nil)
	if err != nil {
		return EthernetInventory{}, err
	}
	ports := make(map[string]EthernetPort)
	if err := collectEthernetPorts(response.Body, ports); err != nil {
		return EthernetInventory{}, err
	}
	if len(ports) == 0 {
		return EthernetInventory{}, errNoPorts
	}
	ids := make([]string, 0, len(ports))
	for id := range ports {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]EthernetPort, 0, len(ids))
	for _, id := range ids {
		result = append(result, ports[id])
	}
	return EthernetInventory{
		Ports: result,
		Response: ResponseMetadata{
			Status:      response.Status,
			ContentType: response.ContentType,
			BodyBytes:   response.BodyBytes,
			BodySHA256:  response.BodySHA256,
		},
	}, nil
}

// collectEthernetPorts recursively walks RCI JSON, retaining only records typed as physical Port.
func collectEthernetPorts(data json.RawMessage, ports map[string]EthernetPort) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return errBadPort
	}
	switch trimmed[0] {
	case '{':
		var members map[string]json.RawMessage
		if err := json.Unmarshal(data, &members); err != nil {
			return errBadPort
		}
		if rawID, ok := members["id"]; ok {
			var id string
			if json.Unmarshal(rawID, &id) == nil && portIDPattern.MatchString(id) {
				port, err := parseEthernetPort(id, members)
				if err != nil {
					return err
				}
				if existing, found := ports[id]; found {
					merged, err := mergeEthernetPort(existing, port)
					if err != nil {
						return err
					}
					ports[id] = merged
				} else {
					ports[id] = port
				}
			}
		}
		for _, child := range members {
			if err := collectEthernetPorts(child, ports); err != nil {
				return err
			}
		}
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return errBadPort
		}
		for _, item := range items {
			if err := collectEthernetPorts(item, ports); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseEthernetPort validates the fields used by the connector and ignores unrelated RCI fields.
func parseEthernetPort(id string, members map[string]json.RawMessage) (EthernetPort, error) {
	var kind, link string
	if json.Unmarshal(members["type"], &kind) != nil || kind != "Port" || json.Unmarshal(members["link"], &link) != nil {
		return EthernetPort{}, errBadPort
	}
	port := EthernetPort{ID: id}
	switch link {
	case "down":
		port.Link = LinkDown
	case "up":
		port.Link = LinkUp
	default:
		return EthernetPort{}, errBadPort
	}
	if rawSpeed, ok := members["speed"]; ok {
		var text string
		if json.Unmarshal(rawSpeed, &text) != nil {
			return EthernetPort{}, errBadPort
		}
		value, err := strconv.ParseUint(text, 10, 32)
		if err != nil || value == 0 {
			return EthernetPort{}, errBadPort
		}
		speed := uint32(value)
		port.SpeedMbps = &speed
	}
	if rawDuplex, ok := members["duplex"]; ok {
		var text string
		if json.Unmarshal(rawDuplex, &text) != nil {
			return EthernetPort{}, errBadPort
		}
		var duplex Duplex
		switch text {
		case "half":
			duplex = DuplexHalf
		case "full":
			duplex = DuplexFull
		default:
			return EthernetPort{}, errBadPort
		}
		port.Duplex = &duplex
	}
	return port, nil
}

// mergeEthernetPort combines repeated RCI records and rejects conflicting state or metadata.
func mergeEthernetPort(left, right EthernetPort) (EthernetPort, error) {
	if left.ID != right.ID || left.Link != right.Link {
		return EthernetPort{}, errBadPort
	}
	merged := left
	if merged.SpeedMbps == nil {
		merged.SpeedMbps = right.SpeedMbps
	} else if right.SpeedMbps != nil && *merged.SpeedMbps != *right.SpeedMbps {
		return EthernetPort{}, errBadPort
	}
	if merged.Duplex == nil {
		merged.Duplex = right.Duplex
	} else if right.Duplex != nil && *merged.Duplex != *right.Duplex {
		return EthernetPort{}, errBadPort
	}
	return merged, nil
}
