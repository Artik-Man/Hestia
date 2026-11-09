//go:build linux

// Command fra-protocol-probe checks whether the target kernel preserves FRA_PROTOCOL on an isolated RPDB rule.
package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

const (
	probeRTMNewRule    = 32
	probeRTMDelRule    = 33
	probeFRAIIFName    = 3
	probeFRAPriority   = 6
	probeFRAFWMARK     = 10
	probeFRATable      = 15
	probeFRAFWMASK     = 16
	probeFRAProtocol   = 21
	probeRequestAck    = 1 | 4
	probeRequestCreate = 1 | 4 | 0x400 | 0x200
)

// appendAttr encodes one aligned native-endian netlink attribute.
func appendAttr(data []byte, kind uint16, value []byte) []byte {
	length := 4 + len(value)
	start := len(data)
	data = append(data, make([]byte, (length+3)&^3)...)
	binary.NativeEndian.PutUint16(data[start:start+2], uint16(length))
	binary.NativeEndian.PutUint16(data[start+2:start+4], kind)
	copy(data[start+4:start+length], value)
	return data
}

// appendUint32Attr appends a native-endian four-byte attribute value.
func appendUint32Attr(data []byte, kind uint16, value uint32) []byte {
	encoded := make([]byte, 4)
	binary.NativeEndian.PutUint32(encoded, value)
	return appendAttr(data, kind, encoded)
}

// rulePayload constructs an isolated test rule that cannot match live traffic.
func rulePayload() []byte {
	data := make([]byte, 12)
	data[0] = syscall.AF_INET
	data[7] = 1
	data = appendUint32Attr(data, probeFRAPriority, 32090)
	data = appendUint32Attr(data, probeFRAFWMARK, 0xf1234567)
	data = appendUint32Attr(data, probeFRAFWMASK, 0xffffffff)
	data = appendUint32Attr(data, probeFRATable, 39999)
	data = appendAttr(data, probeFRAIIFName, append([]byte("hestia-probe"), 0))
	return appendAttr(data, probeFRAProtocol, []byte{253})
}

// transact sends one RPDB request and returns the kernel's signed netlink acknowledgement status.
func transact(fd int, messageType, flags uint16, sequence uint32) (int32, error) {
	body := rulePayload()
	message := make([]byte, 16+len(body))
	binary.NativeEndian.PutUint32(message[0:4], uint32(len(message)))
	binary.NativeEndian.PutUint16(message[4:6], messageType)
	binary.NativeEndian.PutUint16(message[6:8], flags)
	binary.NativeEndian.PutUint32(message[8:12], sequence)
	copy(message[16:], body)
	if err := syscall.Sendto(fd, message, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return 0, err
	}
	response := make([]byte, 4096)
	count, _, err := syscall.Recvfrom(fd, response, 0)
	if err != nil {
		return 0, err
	}
	if count < 36 || binary.NativeEndian.Uint16(response[4:6]) != syscall.NLMSG_ERROR ||
		binary.NativeEndian.Uint32(response[8:12]) != sequence {
		return 0, fmt.Errorf("unexpected route-netlink acknowledgement")
	}
	return int32(binary.NativeEndian.Uint32(response[16:20])), nil
}

// main adds the non-matching probe rule, reports the ACK, and deletes it immediately if accepted.
func main() {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	addStatus, err := transact(fd, probeRTMNewRule, probeRequestCreate, 1)
	if err != nil {
		panic(err)
	}
	fmt.Printf("newrule_ack=%d\n", addStatus)
	if addStatus != 0 {
		return
	}
	deleteStatus, err := transact(fd, probeRTMDelRule, probeRequestAck, 2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("delrule_ack=%d\n", deleteStatus)
	if deleteStatus != 0 {
		panic("probe rule was accepted but cleanup failed")
	}
}
