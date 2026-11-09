package keeneticrci

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	policyConfigPath  = "/rci/ip/policy"
	policyRuntimePath = "/rci/show/ip/policy"
)

var (
	policyKeyPattern = regexp.MustCompile(`^Policy([0-9]+)$`)
	opkgTunPattern   = regexp.MustCompile(`^OpkgTun[0-9]{1,2}$`)
)

// IPPolicy contains the non-secret routing identity and OpkgTun permission of one Keenetic access policy.
type IPPolicy struct {
	Key               string
	Table4            uint32
	Mark4             uint32
	OpkgTunInterfaces []string
}

type ipPolicyConfig struct {
	Permit []ipPolicyPermit `json:"permit"`
}

type ipPolicyPermit struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
}

type ipPolicyRuntime struct {
	Mark   string `json:"mark"`
	Table4 uint32 `json:"table4"`
}

// ReadIPPolicies joins the current Keenetic policy configuration with its runtime IPv4 table and mark identities.
func (c *Client) ReadIPPolicies(ctx context.Context) ([]IPPolicy, error) {
	configResponse, err := c.Do(ctx, Operation{Name: "read_ip_policy_config", Path: policyConfigPath, Method: MethodGet}, nil)
	if err != nil {
		return nil, err
	}
	runtimeResponse, err := c.Do(ctx, Operation{Name: "read_ip_policy_runtime", Path: policyRuntimePath, Method: MethodGet}, nil)
	if err != nil {
		return nil, err
	}
	return joinIPPolicies(configResponse.Body, runtimeResponse.Body)
}

// joinIPPolicies combines independently read policy records only when every configuration key has one runtime identity.
func joinIPPolicies(configData, runtimeData json.RawMessage) ([]IPPolicy, error) {
	config, err := decodeIPPolicyConfig(configData)
	if err != nil {
		return nil, err
	}
	runtime, err := decodeIPPolicyRuntime(runtimeData)
	if err != nil {
		return nil, err
	}
	if len(config) == 0 || len(config) != len(runtime) {
		return nil, &Error{Kind: ErrorSchema}
	}
	keys := make([]string, 0, len(config))
	for key := range config {
		if _, ok := runtime[key]; !ok {
			return nil, &Error{Kind: ErrorSchema}
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(left, right int) bool {
		leftMatch := policyKeyPattern.FindStringSubmatch(keys[left])
		rightMatch := policyKeyPattern.FindStringSubmatch(keys[right])
		leftID, _ := strconv.Atoi(leftMatch[1])
		rightID, _ := strconv.Atoi(rightMatch[1])
		return leftID < rightID
	})
	result := make([]IPPolicy, 0, len(keys))
	seenTables := make(map[uint32]struct{}, len(keys))
	seenMarks := make(map[uint32]struct{}, len(keys))
	for _, key := range keys {
		identity, ok := runtime[key]
		if !ok || !validPolicyTable(identity.Table4) {
			return nil, &Error{Kind: ErrorSchema}
		}
		mark, err := parsePolicyMark(identity.Mark)
		if err != nil {
			return nil, err
		}
		policy := IPPolicy{
			Key: key, Table4: identity.Table4, Mark4: mark,
			OpkgTunInterfaces: enabledOpkgTunInterfaces(config[key].Permit),
		}
		if err := policy.Validate(); err != nil {
			return nil, &Error{Kind: ErrorSchema}
		}
		if _, exists := seenTables[policy.Table4]; exists {
			return nil, &Error{Kind: ErrorSchema}
		}
		if _, exists := seenMarks[policy.Mark4]; exists {
			return nil, &Error{Kind: ErrorSchema}
		}
		seenTables[policy.Table4] = struct{}{}
		seenMarks[policy.Mark4] = struct{}{}
		result = append(result, policy)
	}
	return result, nil
}

// decodeIPPolicyConfig validates the policy keys and enabled-interface entries without retaining descriptions.
func decodeIPPolicyConfig(data json.RawMessage) (map[string]ipPolicyConfig, error) {
	var result map[string]ipPolicyConfig
	if err := json.Unmarshal(data, &result); err != nil || len(result) == 0 {
		return nil, &Error{Kind: ErrorSchema}
	}
	for key, policy := range result {
		if !policyKeyPattern.MatchString(key) || policy.Permit == nil {
			return nil, &Error{Kind: ErrorSchema}
		}
		for _, permit := range policy.Permit {
			if (permit.Enabled && permit.Interface == "") || !utf8.ValidString(permit.Interface) {
				return nil, &Error{Kind: ErrorSchema}
			}
		}
	}
	return result, nil
}

// decodeIPPolicyRuntime validates the dynamic IPv4 table and mark record for each Keenetic policy key.
func decodeIPPolicyRuntime(data json.RawMessage) (map[string]ipPolicyRuntime, error) {
	var result map[string]ipPolicyRuntime
	if err := json.Unmarshal(data, &result); err != nil || len(result) == 0 {
		return nil, &Error{Kind: ErrorSchema}
	}
	for key, policy := range result {
		if !policyKeyPattern.MatchString(key) || policy.Mark == "" || policy.Table4 == 0 {
			return nil, &Error{Kind: ErrorSchema}
		}
	}
	return result, nil
}

// enabledOpkgTunInterfaces returns the sorted unique OpkgTun names explicitly permitted by a policy.
func enabledOpkgTunInterfaces(entries []ipPolicyPermit) []string {
	seen := make(map[string]struct{})
	for _, entry := range entries {
		if entry.Enabled && opkgTunPattern.MatchString(entry.Interface) {
			seen[entry.Interface] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// validPolicyTable accepts dynamic Keenetic policy tables above the legacy single-byte route table range.
func validPolicyTable(table uint32) bool { return table >= 256 && table <= 65535 }

// parsePolicyMark parses only marks in the observed Keenetic IPv4 access-policy allocation range.
func parsePolicyMark(value string) (uint32, error) {
	markText := strings.TrimPrefix(strings.ToLower(value), "0x")
	mark, err := strconv.ParseUint(markText, 16, 32)
	if err != nil || mark < 0x0ffff000 || mark > 0x0fffffff {
		return 0, &Error{Kind: ErrorSchema}
	}
	return uint32(mark), nil
}

// Validate ensures every policy key has a matching runtime record before returning any policy identity.
func (policy IPPolicy) Validate() error {
	if !policyKeyPattern.MatchString(policy.Key) || !validPolicyTable(policy.Table4) ||
		policy.Mark4 < 0x0ffff000 || policy.Mark4 > 0x0fffffff {
		return errors.New("invalid Keenetic IPv4 policy identity")
	}
	for index, name := range policy.OpkgTunInterfaces {
		if !opkgTunPattern.MatchString(name) || (index > 0 && policy.OpkgTunInterfaces[index-1] >= name) {
			return errors.New("invalid Keenetic OpkgTun policy selection")
		}
	}
	return nil
}
