//go:build keenetic

package keeneticroute

import (
	"encoding/binary"
	"errors"
	"strings"
)

const (
	ingressRTADestination       = 1
	ingressRTASource            = 2
	ingressRTAOIF               = 4
	ingressRTAGateway           = 5
	ingressRTAPriority          = 6
	ingressRTATable             = 15
	ingressRTACacheInfo         = 12
	ingressFRAIIFName           = 3
	ingressFRAPriority          = 6
	ingressFRASuppressIfGroup   = 13
	ingressFRASuppressPrefixlen = 14
	ingressFRAFWMARK            = 10
	ingressFRATable             = 15
	ingressFRAFWMASK            = 16
	ingressFRAProtocol          = 21
)

type ingressAttribute struct {
	kind  uint16
	value []byte
}

// parseIngressAttributes validates aligned route-netlink attributes after a fixed message header.
func parseIngressAttributes(data []byte, headerSize int) ([]ingressAttribute, error) {
	if headerSize < 0 || len(data) < headerSize {
		return nil, errors.New("invalid route-netlink message header")
	}
	data = data[headerSize:]
	var attributes []ingressAttribute
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, errors.New("truncated route-netlink attribute header")
		}
		length := int(binary.NativeEndian.Uint16(data[:2]))
		if length < 4 || length > len(data) {
			return nil, errors.New("invalid route-netlink attribute length")
		}
		attributes = append(attributes, ingressAttribute{
			kind: binary.NativeEndian.Uint16(data[2:4]), value: data[4:length],
		})
		aligned := (length + 3) &^ 3
		if aligned > len(data) {
			if length == len(data) {
				break
			}
			return nil, errors.New("truncated route-netlink attribute padding")
		}
		data = data[aligned:]
	}
	return attributes, nil
}

// appendNetlinkAttr appends one native-endian netlink attribute with required four-byte alignment.
func appendNetlinkAttr(data []byte, kind uint16, value []byte) []byte {
	length := 4 + len(value)
	start := len(data)
	data = append(data, make([]byte, (length+3)&^3)...)
	binary.NativeEndian.PutUint16(data[start:start+2], uint16(length))
	binary.NativeEndian.PutUint16(data[start+2:start+4], kind)
	copy(data[start+4:start+length], value)
	return data
}

// nativeUint32 encodes a native-endian integer for Linux netlink attributes.
func nativeUint32(value uint32) []byte {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, value)
	return data
}

// decodeIngressRule decodes one RPDB message and rejects malformed or duplicate selectors before collision analysis.
func decodeIngressRule(data []byte) (ingressRule, error) {
	if len(data) < 12 || (data[0] != ingressIPv4Family && data[0] != ingressIPv6Family) {
		return ingressRule{}, errors.New("invalid IP policy rule header")
	}
	attrs, err := parseIngressAttributes(data, 12)
	if err != nil {
		return ingressRule{}, err
	}
	rule := ingressRule{
		Family: data[0], Table: uint32(data[4]), Action: ingressRuleAction(data[7]),
		DestPrefixBits: data[1], SourcePrefixBits: data[2], TOS: data[3],
		Flags: binary.NativeEndian.Uint32(data[8:12]),
	}
	seen := make(map[uint16]struct{}, len(attrs))
	for _, attr := range attrs {
		switch attr.kind {
		case ingressFRAPriority, ingressFRASuppressIfGroup, ingressFRASuppressPrefixlen, ingressFRATable, ingressFRAFWMARK, ingressFRAFWMASK, ingressFRAIIFName, ingressFRAProtocol:
			if _, exists := seen[attr.kind]; exists {
				return ingressRule{}, errors.New("duplicate IP policy rule selector")
			}
			seen[attr.kind] = struct{}{}
		}
		switch attr.kind {
		case ingressFRAPriority:
			if len(attr.value) != 4 {
				return ingressRule{}, errors.New("invalid IP policy rule priority")
			}
			rule.Priority = binary.NativeEndian.Uint32(attr.value)
		case ingressFRATable:
			if len(attr.value) != 4 {
				return ingressRule{}, errors.New("invalid IP policy rule table")
			}
			rule.Table = binary.NativeEndian.Uint32(attr.value)
		case ingressFRAFWMARK:
			if len(attr.value) != 4 {
				return ingressRule{}, errors.New("invalid IP policy rule mark")
			}
			rule.Mark = binary.NativeEndian.Uint32(attr.value)
			rule.HasMark = true
		case ingressFRAFWMASK:
			if len(attr.value) != 4 {
				return ingressRule{}, errors.New("invalid IP policy rule mark mask")
			}
			rule.Mask = binary.NativeEndian.Uint32(attr.value)
		case ingressFRAIIFName:
			if len(attr.value) < 2 || attr.value[len(attr.value)-1] != 0 || strings.IndexByte(string(attr.value[:len(attr.value)-1]), 0) >= 0 || len(attr.value) > 16 {
				return ingressRule{}, errors.New("invalid IP policy rule input interface")
			}
			rule.Input = string(attr.value[:len(attr.value)-1])
		case ingressFRAProtocol:
			if len(attr.value) != 1 {
				return ingressRule{}, errors.New("invalid IP policy rule protocol")
			}
			rule.Protocol = attr.value[0]
		case ingressFRASuppressIfGroup, ingressFRASuppressPrefixlen:
			if len(attr.value) != 4 {
				return ingressRule{}, errors.New("invalid IP policy rule suppression selector")
			}
			if binary.NativeEndian.Uint32(attr.value) != 0xffffffff {
				rule.HasOtherSelectors = true
			}
		default:
			rule.HasOtherSelectors = true
		}
	}
	return rule, nil
}

// ruleNetlinkPayload encodes a policy mark, input interface, table, priority, and action.
func ruleNetlinkPayload(rule ingressRule) []byte {
	data := make([]byte, 12)
	data[0] = rule.Family
	if rule.Table <= 255 {
		data[4] = byte(rule.Table)
	}
	data[7] = byte(rule.Action)
	data = appendNetlinkAttr(data, ingressFRAPriority, nativeUint32(rule.Priority))
	if rule.HasMark {
		data = appendNetlinkAttr(data, ingressFRAFWMARK, nativeUint32(rule.Mark))
		data = appendNetlinkAttr(data, ingressFRAFWMASK, nativeUint32(rule.Mask))
	}
	if rule.Table > 255 {
		data = appendNetlinkAttr(data, ingressFRATable, nativeUint32(rule.Table))
	}
	if rule.Input != "" {
		data = appendNetlinkAttr(data, ingressFRAIIFName, append([]byte(rule.Input), 0))
	}
	return data
}
