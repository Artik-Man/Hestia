// Package awg parses and normalizes the supported AmneziaWG 3.1 client profile format.
package awg

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const maxProfileBytes = 32 * 1024

var (
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	dnsNamePattern    = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$`)
	uintRangePattern  = regexp.MustCompile(`^[0-9]+(?:-[0-9]+)?$`)
	uintPattern       = regexp.MustCompile(`^[0-9]+$`)
	customI1Pattern   = regexp.MustCompile(`^(?:<t>|<(?:b 0x[0-9a-fA-F]+|r [0-9]+|rd [0-9]+|rc [0-9]+)>)+$`)
)

// Profile contains validated, normalized client settings. SecretConfig must only be written
// to root-owned storage and must never be serialized into a public API response or a log.
type Profile struct {
	Address       []netip.Prefix `json:"-"`
	Endpoint      string         `json:"-"`
	EndpointPort  uint16         `json:"-"`
	AllowedIPs    []netip.Prefix `json:"-"`
	DNS           []netip.Addr   `json:"-"`
	IPv4Address   string         `json:"-"`
	DNSIPv4       string         `json:"-"`
	Protocol      string         `json:"-"`
	IPv6Blocked   bool           `json:"-"`
	SecretConfig  []byte         `json:"-"`
	RuntimeConfig []byte         `json:"-"`
}

// Parse validates one bounded AmneziaWG 3.1 client profile and returns a canonical config.
// It accepts exactly one Interface and one Peer section, rejects unknown directives and
// hooks, and returns generic errors that never contain input values.
func Parse(data []byte) (Profile, error) {
	if len(data) == 0 || len(data) > maxProfileBytes || strings.IndexByte(string(data), 0) >= 0 {
		return Profile{}, errors.New("invalid AmneziaWG profile size or encoding")
	}
	sections := map[string]map[string]string{"Interface": {}, "Peer": {}}
	var section string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024), maxProfileBytes)
	seenSections := make(map[string]bool, 2)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			if _, ok := sections[section]; !ok || seenSections[section] {
				return Profile{}, errors.New("unsupported or duplicate profile section")
			}
			seenSections[section] = true
			continue
		}
		if section == "" {
			return Profile{}, errors.New("profile setting appears outside a supported section")
		}
		key, value, ok := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || key == "" || value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return Profile{}, errors.New("malformed profile setting")
		}
		if _, exists := sections[section][key]; exists {
			return Profile{}, errors.New("duplicate profile setting")
		}
		sections[section][key] = value
	}
	if err := scanner.Err(); err != nil || len(seenSections) != 2 {
		return Profile{}, errors.New("malformed or incomplete profile")
	}
	if err := validateKeys(sections); err != nil {
		return Profile{}, err
	}
	profile, err := normalize(sections)
	if err != nil {
		return Profile{}, err
	}
	profile.SecretConfig = encode(sections)
	profile.RuntimeConfig = encodeRuntime(sections)
	return profile, nil
}

// validateKeys rejects settings that the connector does not explicitly support, including
// shell hooks, route installation controls, and kernel policy settings.
func validateKeys(sections map[string]map[string]string) error {
	allowedInterface := map[string]bool{
		"Address": true, "PrivateKey": true, "DNS": true, "MTU": true, "FwMark": true,
		"Jc": true, "Jmin": true, "Jmax": true, "S1": true, "S2": true, "S3": true, "S4": true,
		"H1": true, "H2": true, "H3": true, "H4": true, "HeaderProtectionKey": true,
		"ContentPaddingAddition": true, "RekeyAfterTime": true, "RekeyTimeout": true,
		"RejectAfterTime": true, "KeepaliveTimeout": true, "MaxHandshakeAttempts": true,
		"RandomTrailers": true, "DisableCookies": true,
		"I1": true, "I2": true, "I3": true, "I4": true, "I5": true,
	}
	allowedPeer := map[string]bool{
		"PublicKey": true, "PresharedKey": true, "Endpoint": true, "AllowedIPs": true,
		"PersistentKeepalive": true,
	}
	for key := range sections["Interface"] {
		if !allowedInterface[key] {
			return errors.New("profile contains an unsupported Interface setting")
		}
	}
	for key := range sections["Peer"] {
		if !allowedPeer[key] {
			return errors.New("profile contains an unsupported Peer setting")
		}
	}
	for _, key := range []string{"Address", "PrivateKey"} {
		if sections["Interface"][key] == "" {
			return errors.New("profile is missing a required Interface setting")
		}
	}
	for _, key := range []string{"PublicKey", "Endpoint", "AllowedIPs"} {
		if sections["Peer"][key] == "" {
			return errors.New("profile is missing a required Peer setting")
		}
	}
	if value := sections["Interface"]["FwMark"]; value != "" && value != "0" {
		return errors.New("nonzero outer transport mark is not supported")
	}
	return nil
}

// normalize validates protocol values and builds the public, non-secret profile metadata.
func normalize(sections map[string]map[string]string) (Profile, error) {
	local := sections["Interface"]
	peer := sections["Peer"]
	addresses, err := prefixes(local["Address"])
	if err != nil {
		return Profile{}, errors.New("invalid interface address")
	}
	allowed, err := prefixes(peer["AllowedIPs"])
	if err != nil {
		return Profile{}, errors.New("invalid allowed address")
	}
	ipv6Blocked := hasIPv6Prefix(addresses) || hasIPv6Prefix(allowed)
	if err := key(local["PrivateKey"]); err != nil {
		return Profile{}, errors.New("invalid private key")
	}
	if err := key(peer["PublicKey"]); err != nil {
		return Profile{}, errors.New("invalid peer key")
	}
	if value := peer["PresharedKey"]; value != "" {
		if err := key(value); err != nil {
			return Profile{}, errors.New("invalid preshared key")
		}
	}
	if value := local["HeaderProtectionKey"]; value != "" {
		if err := key(value); err != nil {
			return Profile{}, errors.New("invalid header protection key")
		}
		for _, name := range []string{"S1", "S2", "S3", "S4"} {
			v, ok := local[name]
			if !ok || integer(v, 12, 65535) != nil {
				return Profile{}, errors.New("header protection requires valid S1-S4 settings")
			}
		}
	}
	if err := validateProtocolValues(local, peer); err != nil {
		return Profile{}, err
	}
	host, portValue, err := net.SplitHostPort(peer["Endpoint"])
	if err != nil || !validEndpointHost(host) {
		return Profile{}, errors.New("invalid peer endpoint")
	}
	portNumber, err := strconv.ParseUint(portValue, 10, 16)
	if err != nil || portNumber == 0 {
		return Profile{}, errors.New("invalid peer endpoint port")
	}
	if endpoint, parseErr := netip.ParseAddr(host); parseErr == nil && !endpoint.Is4() {
		return Profile{}, errors.New("IPv6 peer endpoints are not supported")
	}
	dns, err := addressesList(local["DNS"])
	if err != nil {
		return Profile{}, errors.New("invalid DNS address")
	}
	for _, address := range dns {
		ipv6Blocked = ipv6Blocked || address.Is6()
	}
	ipv4Address, ipv4DNS := "", ""
	for _, address := range addresses {
		if address.Addr().Is4() {
			ipv4Address = address.String()
			break
		}
	}
	for _, address := range dns {
		if address.Is4() {
			ipv4DNS = address.String()
			break
		}
	}
	if ipv4Address == "" || ipv4DNS == "" {
		return Profile{}, errors.New("IPv4 address and DNS are required for this release")
	}
	protocol := "wireguard"
	for _, name := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"} {
		if _, exists := local[name]; exists {
			protocol = "amneziawg"
			break
		}
	}
	return Profile{Address: addresses, Endpoint: host, EndpointPort: uint16(portNumber), AllowedIPs: allowed, DNS: dns, IPv4Address: ipv4Address, DNSIPv4: ipv4DNS, Protocol: protocol, IPv6Blocked: ipv6Blocked}, nil
}

// hasIPv6Prefix reports whether any configured prefix belongs to IPv6, which the route policy blocks in release one.
func hasIPv6Prefix(prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() {
			return true
		}
	}
	return false
}

// validateProtocolValues checks bounded integer/range parameters and safe AWG 3.1 I1 grammar.
func validateProtocolValues(local, peer map[string]string) error {
	for _, name := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"} {
		if value, ok := local[name]; ok {
			if integer(value, 0, 65535) != nil {
				return errors.New("invalid protocol integer setting")
			}
		}
	}
	if value, ok := local["MTU"]; ok && integer(value, 576, 9000) != nil {
		return errors.New("invalid interface MTU")
	}
	for _, name := range []string{"H1", "H2", "H3", "H4", "ContentPaddingAddition"} {
		if value, ok := local[name]; ok {
			max := uint64(4294967295)
			if name == "ContentPaddingAddition" {
				max = 65535
			}
			if validateRangeMax(value, max) != nil {
				return errors.New("invalid protocol range setting")
			}
		}
	}
	for _, name := range []string{"RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"} {
		if value, ok := local[name]; ok && validateRangeMax(value, 65535) != nil {
			return errors.New("invalid protocol range setting")
		}
	}
	for _, name := range []string{"RandomTrailers", "DisableCookies"} {
		if value, ok := local[name]; ok && !validBool(value) {
			return errors.New("invalid protocol boolean setting")
		}
	}
	if min, ok := local["Jmin"]; ok {
		if max, exists := local["Jmax"]; exists && numericMax(min) > numericMax(max) {
			return errors.New("invalid junk packet range")
		}
	}
	for name, value := range local {
		if strings.HasPrefix(name, "I") && !customI1Pattern.MatchString(value) {
			return errors.New("invalid custom signature setting")
		}
	}
	if value := peer["PersistentKeepalive"]; value != "" && validateRangeMax(value, 65535) != nil {
		return errors.New("invalid persistent keepalive setting")
	}
	return nil
}

// prefixes parses a comma-separated address/prefix list and returns canonical prefixes.
func prefixes(value string) ([]netip.Prefix, error) {
	parts := strings.Split(value, ",")
	result := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil || !prefix.IsValid() {
			return nil, errors.New("invalid prefix")
		}
		result = append(result, prefix.Masked())
	}
	if len(result) == 0 {
		return nil, errors.New("empty prefix list")
	}
	return result, nil
}

// addressesList parses an optional comma-separated list of literal IP addresses.
func addressesList(value string) ([]netip.Addr, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	result := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || !address.IsValid() || address.Zone() != "" {
			return nil, errors.New("invalid DNS address")
		}
		result = append(result, address)
	}
	return result, nil
}

// key validates the base64 encoding and exact WireGuard key length.
func key(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return errors.New("invalid key")
	}
	return nil
}

// integer requires one unsigned decimal value within the supplied inclusive bounds.
func integer(value string, min, max uint64) error {
	if !uintPattern.MatchString(value) {
		return errors.New("invalid integer")
	}
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number < min || number > max {
		return errors.New("integer out of range")
	}
	return nil
}

// validateRangeMax applies the AmneziaWG uint range grammar with the supplied maximum.
func validateRangeMax(value string, max uint64) error {
	if !uintRangePattern.MatchString(value) {
		return errors.New("invalid range")
	}
	parts := strings.Split(value, "-")
	if len(parts) == 1 {
		return integer(parts[0], 0, max)
	}
	if integer(parts[0], 0, max) != nil || integer(parts[1], 0, max) != nil || numericMax(parts[0]) > numericMax(parts[1]) {
		return errors.New("invalid range")
	}
	return nil
}

// validBool accepts exactly the spellings recognized by the pinned amneziawg-tools configuration parser.
func validBool(value string) bool {
	return strings.EqualFold(value, "on") || strings.EqualFold(value, "off") || value == "0" || value == "1"
}

// numericMax returns the parsed unsigned value or zero when parsing fails.
func numericMax(value string) uint64 {
	number, _ := strconv.ParseUint(value, 10, 64)
	return number
}

// validEndpointHost accepts a literal IP address or an ASCII DNS name without zones.
func validEndpointHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.IsValid() && address.Zone() == ""
	}
	return len(host) <= 253 && dnsNamePattern.MatchString(host)
}

// encode serializes validated settings into deterministic awg-tools input for root-only storage.
func encode(sections map[string]map[string]string) []byte {
	var output strings.Builder
	for _, section := range []string{"Interface", "Peer"} {
		fmt.Fprintf(&output, "[%s]\n", section)
		keys := make([]string, 0, len(sections[section]))
		for key := range sections[section] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Fprintf(&output, "%s = %s\n", key, sections[section][key])
		}
		output.WriteByte('\n')
	}
	return []byte(output.String())
}

// encodeRuntime serializes only UAPI settings and omits interface addresses, DNS, MTU and outer fwmark.
func encodeRuntime(sections map[string]map[string]string) []byte {
	filtered := map[string]map[string]string{"Interface": {}, "Peer": sections["Peer"]}
	for key, value := range sections["Interface"] {
		if key != "Address" && key != "DNS" && key != "MTU" && key != "FwMark" {
			filtered["Interface"][key] = value
		}
	}
	return encode(filtered)
}
