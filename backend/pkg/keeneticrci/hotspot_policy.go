package keeneticrci

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

const (
	hotspotHostsRuntimePath = "/rci/show/ip/hotspot"
	hotspotHostsConfigPath  = "/rci/ip/hotspot/host"
)

var (
	hotspotMACPattern  = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	hotspotPolicyMatch = regexp.MustCompile(`^Policy[0-9]{1,10}$`)
)

// ClientPolicyAssignment reports only whether one source IPv4 address maps to one explicit client policy.
type ClientPolicyAssignment struct {
	PolicyKey string
	Found     bool
	Explicit  bool
}

type hotspotRuntimeResponse struct {
	Hosts []hotspotRuntimeHost `json:"host"`
}

type hotspotRuntimeHost struct {
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Active    bool   `json:"active"`
	Interface struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"interface"`
}

type hotspotHostConfiguration struct {
	Hosts json.RawMessage `json:"host"`
}

// ReadClientPolicyAssignment resolves a unique active source IPv4 host to its explicit configured Keenetic policy.
func (c *Client) ReadClientPolicyAssignment(ctx context.Context, source string) (ClientPolicyAssignment, error) {
	address, err := netip.ParseAddr(source)
	if err != nil || !address.Is4() {
		return ClientPolicyAssignment{}, &Error{Kind: ErrorInvalidOperation}
	}
	runtimeResponse, err := c.Do(ctx, Operation{Name: "read_hotspot_hosts_runtime", Path: hotspotHostsRuntimePath, Method: MethodGet}, nil)
	if err != nil {
		return ClientPolicyAssignment{}, err
	}
	mac, found, err := matchHotspotHost(runtimeResponse.Body, address)
	if err != nil || !found {
		return ClientPolicyAssignment{Found: found}, err
	}
	configResponse, err := c.Do(ctx, Operation{Name: "read_hotspot_hosts_config", Path: hotspotHostsConfigPath, Method: MethodGet}, nil)
	if err != nil {
		return ClientPolicyAssignment{}, err
	}
	policy, explicit, err := matchHotspotHostPolicy(configResponse.Body, mac)
	if err != nil {
		return ClientPolicyAssignment{}, err
	}
	if !explicit {
		return ClientPolicyAssignment{Found: true}, nil
	}
	if !hotspotPolicyMatch.MatchString(policy) {
		return ClientPolicyAssignment{}, &Error{Kind: ErrorSchema}
	}
	return ClientPolicyAssignment{PolicyKey: policy, Found: true, Explicit: true}, nil
}

// matchHotspotHost extracts one host's MAC only in memory when exactly one active entry has the requested IPv4 address.
func matchHotspotHost(data json.RawMessage, source netip.Addr) (string, bool, error) {
	var response hotspotRuntimeResponse
	if err := json.Unmarshal(data, &response); err != nil || response.Hosts == nil {
		return "", false, &Error{Kind: ErrorSchema}
	}
	matched := ""
	for _, host := range response.Hosts {
		if !host.Active {
			continue
		}
		address, err := netip.ParseAddr(host.IP)
		if err != nil || !address.Is4() || address != source {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(host.MAC))
		if !hotspotMACPattern.MatchString(mac) || matched != "" {
			return "", false, &Error{Kind: ErrorSchema}
		}
		matched = mac
	}
	return matched, matched != "", nil
}

// matchHotspotHostPolicy reads one explicit per-client policy without retaining or returning the client's MAC.
func matchHotspotHostPolicy(data json.RawMessage, mac string) (string, bool, error) {
	var response hotspotHostConfiguration
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", false, &Error{Kind: ErrorSchema}
	}
	if trimmed[0] == '[' {
		response.Hosts = trimmed
	} else if err := json.Unmarshal(trimmed, &response); err != nil {
		return "", false, &Error{Kind: ErrorSchema}
	}
	if response.Hosts == nil {
		var root map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &root); err != nil || root == nil {
			return "", false, &Error{Kind: ErrorSchema}
		}
		response.Hosts = trimmed
	}
	var list []struct {
		MAC    string `json:"mac"`
		Policy string `json:"policy"`
	}
	hostData := bytes.TrimSpace(response.Hosts)
	if len(hostData) > 0 && hostData[0] == '[' {
		if err := json.Unmarshal(hostData, &list); err != nil {
			return "", false, &Error{Kind: ErrorSchema}
		}
		matched, found := "", false
		for _, host := range list {
			if !strings.EqualFold(host.MAC, mac) {
				continue
			}
			if found {
				return "", false, &Error{Kind: ErrorSchema}
			}
			matched, found = host.Policy, true
		}
		if !found || matched == "" {
			return "", false, nil
		}
		if !hotspotPolicyMatch.MatchString(matched) {
			return "", false, &Error{Kind: ErrorSchema}
		}
		return matched, true, nil
	}
	var hostMap map[string]json.RawMessage
	if err := json.Unmarshal(response.Hosts, &hostMap); err != nil || hostMap == nil {
		return "", false, &Error{Kind: ErrorSchema}
	}
	matched, found := "", false
	for key, raw := range hostMap {
		if !strings.EqualFold(key, mac) {
			continue
		}
		if found {
			return "", false, &Error{Kind: ErrorSchema}
		}
		found = true
		var host struct {
			Policy string `json:"policy"`
		}
		if err := json.Unmarshal(raw, &host); err != nil {
			return "", false, &Error{Kind: ErrorSchema}
		}
		matched = host.Policy
	}
	if !found {
		return "", false, nil
	}
	if matched == "" {
		return "", false, nil
	}
	if !hotspotPolicyMatch.MatchString(matched) {
		return "", false, &Error{Kind: ErrorSchema}
	}
	return matched, true, nil
}
