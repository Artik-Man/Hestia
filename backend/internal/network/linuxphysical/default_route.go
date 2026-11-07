package linuxphysical

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
)

// MainDefaultRouteDevice returns the unique Linux main-table device with the lowest-metric IPv4 default route.
// An absent route or a tie between devices returns an empty name so callers can omit uncertain labels.
func MainDefaultRouteDevice() (string, error) {
	return mainDefaultRouteDeviceAt("/proc/net/route")
}

// mainDefaultRouteDeviceAt reads a Linux route-table file and returns its unique active IPv4 default-route device.
// It ignores malformed rows, routes without the UP flag, and ties that cannot be resolved safely.
func mainDefaultRouteDeviceAt(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() { // Skip the column header.
		if err := scanner.Err(); err != nil {
			return "", err
		}
		return "", errors.New("empty route table")
	}
	var device string
	var metric uint64
	ambiguous := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || !deviceName.MatchString(fields[0]) || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&1 == 0 {
			continue
		}
		rowMetric, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			continue
		}
		if device == "" || rowMetric < metric {
			device, metric, ambiguous = fields[0], rowMetric, false
			continue
		}
		if rowMetric == metric && fields[0] != device {
			ambiguous = true
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if ambiguous {
		return "", nil
	}
	return device, nil
}
