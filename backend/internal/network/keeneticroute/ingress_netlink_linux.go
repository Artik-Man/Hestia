//go:build linux && keenetic

package keeneticroute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

const (
	ingressNLMRequest = 1
	ingressNLMAck     = 4
	maxIngressAckWait = 3 * time.Second
)

// NetlinkIngressOps implements isolated Hestia ingress routes and rules using Linux route netlink.
type NetlinkIngressOps struct {
	OwnershipPath string
}

// Routes returns IPv4 routes from one requested table, or every table when table is zero.
func (NetlinkIngressOps) Routes(ctx context.Context, table uint32) ([]ingressRoute, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, errors.New("cannot read IPv4 routes from route netlink")
	}
	messages, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, errors.New("cannot decode IPv4 route dump")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("cannot inspect network interfaces")
	}
	names := make(map[int]string, len(interfaces))
	for _, iface := range interfaces {
		names[iface.Index] = iface.Name
	}
	var result []ingressRoute
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWROUTE {
			continue
		}
		if len(message.Data) < 12 {
			return nil, errors.New("cannot decode IPv4 route header")
		}
		if message.Data[0] != syscall.AF_INET {
			continue
		}
		attrs, err := parseIngressAttributes(message.Data, 12)
		if err != nil {
			return nil, errors.New("cannot decode IPv4 route attributes")
		}
		var currentTable, metric uint32 = uint32(message.Data[4]), 0
		var outputIndex int32
		prefixBits, sourcePrefixBits, tos := message.Data[1], message.Data[2], message.Data[3]
		hasGateway, hasOtherAttributes := false, false
		seen := make(map[uint16]struct{}, len(attrs))
		for _, attr := range attrs {
			switch attr.kind {
			case ingressRTADestination, ingressRTASource, ingressRTATable, ingressRTAPriority, ingressRTAOIF, ingressRTAGateway:
				if _, exists := seen[attr.kind]; exists {
					return nil, errors.New("duplicate IPv4 route attribute")
				}
				seen[attr.kind] = struct{}{}
			}
			switch attr.kind {
			case ingressRTADestination:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route destination")
				}
				if !bytes.Equal(attr.value, []byte{0, 0, 0, 0}) {
					hasOtherAttributes = true
				}
			case ingressRTASource:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route source")
				}
				hasOtherAttributes = true
			case ingressRTATable:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route table")
				}
				currentTable = binary.NativeEndian.Uint32(attr.value)
			case ingressRTAPriority:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route metric")
				}
				metric = binary.NativeEndian.Uint32(attr.value)
			case ingressRTAOIF:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route output interface")
				}
				outputIndex = int32(binary.NativeEndian.Uint32(attr.value))
			case ingressRTAGateway:
				if len(attr.value) != 4 {
					return nil, errors.New("invalid IPv4 route gateway")
				}
				hasGateway = true
			case ingressRTACacheInfo:
				// Kernel cache metadata does not change route selection.
			default:
				hasOtherAttributes = true
			}
		}
		if table != 0 && currentTable != table {
			continue
		}
		device := names[int(outputIndex)]
		routeType := ingressRouteType(message.Data[7])
		result = append(result, ingressRoute{
			Table: currentTable, PrefixBits: prefixBits, SourcePrefixBits: sourcePrefixBits, TOS: tos,
			Type: routeType, Scope: message.Data[6], Protocol: message.Data[5], Flags: binary.NativeEndian.Uint32(message.Data[8:12]),
			Metric: metric, Device: device, HasGateway: hasGateway, HasOtherAttributes: hasOtherAttributes,
		})
	}
	return result, nil
}

// Rules returns IPv4 and IPv6 policy rules with the selectors used by Hestia and Keenetic.
func (ops NetlinkIngressOps) Rules(ctx context.Context) ([]ingressRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ops.OwnershipPath == "" {
		return nil, errors.New("Hestia ingress rule ownership path is unavailable")
	}
	var result []ingressRule
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		data, err := syscall.NetlinkRIB(syscall.RTM_GETRULE, family)
		if err != nil {
			return nil, errors.New("cannot read IP policy rules from route netlink")
		}
		messages, err := syscall.ParseNetlinkMessage(data)
		if err != nil {
			return nil, errors.New("cannot decode IP policy rule dump")
		}
		for _, message := range messages {
			if message.Header.Type != syscall.RTM_NEWRULE {
				continue
			}
			if len(message.Data) < 12 {
				return nil, errors.New("cannot decode IP policy rule header")
			}
			if int(message.Data[0]) != family {
				continue
			}
			rule, err := decodeIngressRule(message.Data)
			if err != nil {
				return nil, fmt.Errorf("cannot decode policy rule attributes for address family %d: %w", family, err)
			}
			result = append(result, rule)
		}
	}
	return reconcileOwnedIngressRules(ops.OwnershipPath, result)
}

// LinkUp confirms an exact interface is administratively up.
func (NetlinkIngressOps) LinkUp(ctx context.Context, name string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false, nil
	}
	return iface.Flags&net.FlagUp != 0, nil
}

// AddRoute installs an exact IPv4 route through a bounded acknowledged netlink request.
func (NetlinkIngressOps) AddRoute(ctx context.Context, route ingressRoute) error {
	payload, err := routeNetlinkPayload(route)
	if err != nil {
		return err
	}
	return sendIngressNetlink(ctx, syscall.RTM_NEWROUTE, payload, true)
}

// DeleteRoute deletes an exact IPv4 route through a bounded acknowledged netlink request.
func (NetlinkIngressOps) DeleteRoute(ctx context.Context, route ingressRoute) error {
	payload, err := routeNetlinkPayload(route)
	if err != nil {
		return err
	}
	return sendIngressNetlink(ctx, syscall.RTM_DELROUTE, payload, false)
}

// AddRule installs an exact IPv4 policy rule through a bounded acknowledged netlink request.
func (ops NetlinkIngressOps) AddRule(ctx context.Context, rule ingressRule) error {
	if ops.OwnershipPath == "" || rule.Owned {
		return errors.New("Hestia ingress rule ownership is not configured")
	}
	if err := sendIngressNetlink(ctx, syscall.RTM_NEWRULE, ruleNetlinkPayload(rule), true); err != nil {
		return err
	}
	return addOwnedIngressRule(ops.OwnershipPath, rule, func() error {
		return sendIngressNetlink(context.Background(), syscall.RTM_DELRULE, ruleNetlinkPayload(rule), false)
	})
}

// DeleteRule deletes an exact IPv4 policy rule through a bounded acknowledged netlink request.
func (ops NetlinkIngressOps) DeleteRule(ctx context.Context, rule ingressRule) error {
	if ops.OwnershipPath == "" || !rule.Owned {
		return errors.New("cannot delete an unowned Hestia ingress rule")
	}
	if err := removeOwnedIngressRule(ops.OwnershipPath, rule); err != nil {
		return err
	}
	return sendIngressNetlink(ctx, syscall.RTM_DELRULE, ruleNetlinkPayload(rule), false)
}

// routeNetlinkPayload encodes a default route and its extended table/metric/output interface attributes.
func routeNetlinkPayload(route ingressRoute) ([]byte, error) {
	data := make([]byte, 12)
	data[0] = syscall.AF_INET
	data[1] = route.PrefixBits
	data[5] = byte(route.Protocol)
	if route.Table <= 255 {
		data[4] = byte(route.Table)
	}
	data[7] = byte(route.Type)
	if route.Table > 255 {
		data = appendNetlinkAttr(data, ingressRTATable, nativeUint32(route.Table))
	}
	if route.Metric != 0 {
		data = appendNetlinkAttr(data, ingressRTAPriority, nativeUint32(route.Metric))
	}
	if route.Device != "" {
		iface, err := net.InterfaceByName(route.Device)
		if err != nil {
			return nil, errors.New("route output interface is unavailable")
		}
		data = appendNetlinkAttr(data, ingressRTAOIF, nativeUint32(uint32(iface.Index)))
	}
	return data, nil
}

// sendIngressNetlink sends one route-netlink mutation and waits for its kernel acknowledgement.
func sendIngressNetlink(ctx context.Context, messageType uint16, payload []byte, create bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(maxIngressAckWait)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	flags := uint16(ingressNLMRequest | ingressNLMAck)
	if create {
		flags |= syscall.NLM_F_CREATE | syscall.NLM_F_EXCL
	}
	message := make([]byte, 16+len(payload))
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], messageType)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], 1)
	copy(message[16:], payload)
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return errors.New("cannot open route-netlink socket")
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1}); err != nil {
		return errors.New("cannot bound route-netlink acknowledgement wait")
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return errors.New("cannot bind route-netlink socket")
	}
	if err := syscall.Sendto(fd, message, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return errors.New("cannot send route-netlink request")
	}
	buffer := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, _, err := syscall.Recvfrom(fd, buffer, 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				if !time.Now().Before(deadline) {
					return errors.New("timed out waiting for route-netlink acknowledgement")
				}
				continue
			}
			return errors.New("cannot receive route-netlink acknowledgement")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:count])
		if err != nil {
			return errors.New("cannot decode route-netlink acknowledgement")
		}
		for _, response := range messages {
			if response.Header.Type != syscall.NLMSG_ERROR || response.Header.Seq != 1 || len(response.Data) < 4 {
				continue
			}
			code := int32(binary.NativeEndian.Uint32(response.Data[:4]))
			if code == 0 {
				return nil
			}
			return errors.New("kernel rejected route-netlink request")
		}
	}
}
