//go:build linux

// route_probe is a bounded proof for adding and resolving routes in a Keenetic policy table above 255.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	minimumPolicyTable = 4096
	maximumPolicyTable = 8191
	minimumPolicyMark  = 0x0ffff000
	maximumPolicyMark  = 0x0fffffff
	proofDevice        = "opkgtun0"
	proofIngressDevice = "br0"
	proofClientSource  = "192.168.1.124"
	probeTarget        = "192.0.2.1"
)

// routeIdentity describes the fields the probe may use for one default route.
type routeIdentity struct {
	table    uint32
	metric   uint32
	ifindex  uint32
	routeTyp byte
}

// main runs exactly one proof operation against the fixed temporary table and interface.
func main() {
	if len(os.Args) != 4 {
		fail("expected operation, policy table, and policy mark")
	}
	table, mark, err := parsePolicyIdentity(os.Args[2], os.Args[3])
	if err != nil {
		fail("invalid policy identity")
	}
	switch os.Args[1] {
	case "add-guard":
		err = modifyRoute(routeIdentity{table: table, metric: 32767, routeTyp: unix.RTN_UNREACHABLE}, true)
	case "add-tun":
		var link *net.Interface
		link, err = net.InterfaceByName(proofDevice)
		if err == nil {
			err = modifyRoute(routeIdentity{table: table, metric: 1000, ifindex: uint32(link.Index), routeTyp: unix.RTN_UNICAST}, true)
		}
	case "del-tun":
		var link *net.Interface
		link, err = net.InterfaceByName(proofDevice)
		if err == nil {
			err = modifyRoute(routeIdentity{table: table, metric: 1000, ifindex: uint32(link.Index), routeTyp: unix.RTN_UNICAST}, false)
		}
	case "del-guard":
		err = modifyRoute(routeIdentity{table: table, metric: 32767, routeTyp: unix.RTN_UNREACHABLE}, false)
	case "lookup":
		var result string
		result, err = lookupRoute(table, mark, net.ParseIP(probeTarget).To4())
		if err == nil {
			fmt.Println(result)
		}
	case "delete-link":
		err = deleteTestLink()
	default:
		fail("unsupported operation")
	}
	if err != nil {
		if os.Args[1] == "lookup" && errors.Is(err, unix.EINVAL) {
			fail("route lookup rejected the input tuple")
		}
		fail("route operation failed")
	}
}

// deleteTestLink removes only the known OpkgTun test link after its NDM object and test process are gone.
func deleteTestLink() error {
	link, err := net.InterfaceByName(proofDevice)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("cannot inspect test link")
	}
	body := make([]byte, 16)
	body[0] = unix.AF_UNSPEC
	binary.LittleEndian.PutUint32(body[4:8], uint32(link.Index))
	message := linkMessage(unix.RTM_DELLINK, unix.NLM_F_REQUEST|unix.NLM_F_ACK, body, attribute(3, append([]byte(proofDevice), 0))) // IFLA_IFNAME
	_, err = transact(message, true)
	return err
}

// parsePolicyIdentity accepts only Keenetic policy-table IDs and marks in the observed reserved ranges.
func parsePolicyIdentity(tableText, markText string) (uint32, uint32, error) {
	table, tableErr := strconv.ParseUint(tableText, 10, 32)
	mark, markErr := strconv.ParseUint(strings.TrimPrefix(markText, "0x"), 16, 32)
	if tableErr != nil || markErr != nil || table < minimumPolicyTable || table > maximumPolicyTable || mark < minimumPolicyMark || mark > maximumPolicyMark {
		return 0, 0, errors.New("invalid route policy identity")
	}
	return uint32(table), uint32(mark), nil
}

// fail prints one fixed diagnostic and exits without exposing kernel payloads.
func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

// modifyRoute adds or deletes one default route in the fixed policy table and waits for the kernel ACK.
func modifyRoute(route routeIdentity, add bool) error {
	if route.table < minimumPolicyTable || route.table > maximumPolicyTable || route.metric == 0 || route.routeTyp != unix.RTN_UNREACHABLE && route.routeTyp != unix.RTN_UNICAST {
		return errors.New("invalid proof route")
	}
	if (route.routeTyp == unix.RTN_UNREACHABLE && route.ifindex != 0) || (route.routeTyp == unix.RTN_UNICAST && route.ifindex == 0) {
		return errors.New("invalid proof interface")
	}
	messageType, flags := uint16(unix.RTM_DELROUTE), uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	if add {
		messageType = unix.RTM_NEWROUTE
		flags |= unix.NLM_F_CREATE | unix.NLM_F_EXCL
	}
	attributes := [][]byte{
		attribute(15, uint32Attribute(route.table)), // RTA_TABLE
		attribute(6, uint32Attribute(route.metric)), // RTA_PRIORITY
	}
	if route.ifindex != 0 {
		attributes = append(attributes, attribute(4, uint32Attribute(route.ifindex))) // RTA_OIF
	}
	message := routeMessage(messageType, flags, route.routeTyp, attributes...)
	_, err := transact(message, true)
	return err
}

// lookupRoute asks the kernel to resolve one forwarded destination using the temporary mark and LAN ingress interface.
func lookupRoute(expectedTable, mark uint32, destination []byte) (string, error) {
	if expectedTable < minimumPolicyTable || expectedTable > maximumPolicyTable || mark < minimumPolicyMark || mark > maximumPolicyMark || len(destination) != net.IPv4len {
		return "", errors.New("invalid proof lookup")
	}
	ingress, err := net.InterfaceByName(proofIngressDevice)
	if err != nil {
		return "", errors.New("cannot inspect proof ingress")
	}
	source := net.ParseIP(proofClientSource).To4()
	attributes := [][]byte{
		attribute(1, destination),                            // RTA_DST
		attribute(2, source),                                 // RTA_SRC
		attribute(3, uint32Attribute(uint32(ingress.Index))), // RTA_IIF
		attribute(16, uint32Attribute(mark)),                 // RTA_MARK
	}
	request := routeMessage(unix.RTM_GETROUTE, unix.NLM_F_REQUEST, unix.RTN_UNICAST, attributes...)
	binary.LittleEndian.PutUint32(request[24:28], unix.RTM_F_LOOKUP_TABLE)
	response, err := transact(request, false)
	if err != nil {
		if errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.ENETUNREACH) {
			return "type=unreachable", nil
		}
		return "", err
	}
	if len(response) < 12 || response[0] != unix.AF_INET {
		return "", errors.New("invalid route response")
	}
	messageTable := uint32(response[4])
	messageType := response[7]
	var routeTable, ifindex uint32
	for _, item := range parseAttributes(response[12:]) {
		switch item.kind {
		case 15: // RTA_TABLE
			if len(item.value) == 4 {
				routeTable = binary.LittleEndian.Uint32(item.value)
			}
		case 4: // RTA_OIF
			if len(item.value) == 4 {
				ifindex = binary.LittleEndian.Uint32(item.value)
			}
		}
	}
	if routeTable == 0 {
		routeTable = messageTable
	}
	linkName := "none"
	if ifindex != 0 {
		link, lookupErr := net.InterfaceByIndex(int(ifindex))
		if lookupErr != nil {
			return "", errors.New("cannot identify route device")
		}
		linkName = link.Name
	}
	return fmt.Sprintf("expected_table_id=%d actual_table_id=%d device=%s route_type=%d", expectedTable, routeTable, linkName, messageType), nil
}

// routeMessage encodes one IPv4 netlink route message with the supplied route attributes.
func routeMessage(messageType, flags uint16, routeType byte, attributes ...[]byte) []byte {
	body := make([]byte, 12)
	body[0] = unix.AF_INET
	body[4] = unix.RT_TABLE_UNSPEC
	body[5] = unix.RTPROT_STATIC
	body[6] = unix.RT_SCOPE_UNIVERSE
	body[7] = routeType
	for _, item := range attributes {
		body = append(body, item...)
	}
	message := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:6], messageType)
	binary.LittleEndian.PutUint16(message[6:8], flags)
	copy(message[16:], body)
	return message
}

// linkMessage encodes one netlink link-management request with the provided interface payload and attributes.
func linkMessage(messageType, flags uint16, body []byte, attributes ...[]byte) []byte {
	payload := append([]byte(nil), body...)
	for _, item := range attributes {
		payload = append(payload, item...)
	}
	message := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.LittleEndian.PutUint16(message[4:6], messageType)
	binary.LittleEndian.PutUint16(message[6:8], flags)
	copy(message[16:], payload)
	return message
}

// attribute encodes one netlink route attribute and pads it to a four-byte boundary.
func attribute(kind uint16, value []byte) []byte {
	length := 4 + len(value)
	result := make([]byte, (length+3)&^3)
	binary.LittleEndian.PutUint16(result[0:2], uint16(length))
	binary.LittleEndian.PutUint16(result[2:4], kind)
	copy(result[4:length], value)
	return result
}

// uint32Attribute encodes a netlink attribute value in native little-endian order.
func uint32Attribute(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}

// transact sends one netlink request and returns its matching route payload or ACK status.
func transact(message []byte, waitForAck bool) ([]byte, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, errors.New("cannot open route netlink socket")
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, errors.New("cannot bind route netlink socket")
	}
	message = append([]byte(nil), message...)
	sequence := uint32(os.Getpid()) + 1
	binary.LittleEndian.PutUint32(message[8:12], sequence)
	if err := unix.Sendto(fd, message, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, errors.New("cannot send route netlink request")
	}
	buffer := make([]byte, 65536)
	n, _, err := unix.Recvfrom(fd, buffer, 0)
	if err != nil {
		return nil, errors.New("cannot receive route netlink response")
	}
	messages, err := syscall.ParseNetlinkMessage(buffer[:n])
	if err != nil {
		return nil, errors.New("cannot parse route netlink response")
	}
	for _, response := range messages {
		if response.Header.Seq != sequence {
			continue
		}
		if response.Header.Type == unix.NLMSG_ERROR {
			if len(response.Data) < 4 {
				return nil, errors.New("invalid route netlink acknowledgement")
			}
			code := int32(binary.LittleEndian.Uint32(response.Data[:4]))
			if code == 0 && waitForAck {
				return nil, nil
			}
			if code != 0 {
				return nil, unix.Errno(-code)
			}
		}
		if response.Header.Type == unix.RTM_NEWROUTE && !waitForAck {
			return response.Data, nil
		}
	}
	return nil, errors.New("route netlink response missing")
}

// parseAttributes returns bounded route attributes from one netlink route payload.
func parseAttributes(data []byte) []netlinkAttribute {
	attributes := make([]netlinkAttribute, 0, 4)
	for len(data) >= 4 {
		length := int(binary.LittleEndian.Uint16(data[:2]))
		if length < 4 || length > len(data) {
			return nil
		}
		attributes = append(attributes, netlinkAttribute{
			kind: binary.LittleEndian.Uint16(data[2:4]), value: data[4:length],
		})
		aligned := (length + 3) &^ 3
		if aligned > len(data) {
			return nil
		}
		data = data[aligned:]
	}
	return attributes
}

// netlinkAttribute stores the kind and value of one validated route attribute.
type netlinkAttribute struct {
	kind  uint16
	value []byte
}
