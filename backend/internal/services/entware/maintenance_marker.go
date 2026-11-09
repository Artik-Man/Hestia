package entware

import (
	"strconv"
	"strings"
)

// packageMaintenanceMarker contains the canonical identity of one active opkg transaction.
type packageMaintenanceMarker struct {
	pid       int
	bootID    string
	startTime uint64
}

// parsePackageMaintenanceMarker parses exactly one canonical PID, boot ID, and process start-time record.
func parsePackageMaintenanceMarker(data []byte) (packageMaintenanceMarker, bool) {
	if len(data) == 0 || len(data) > 128 {
		return packageMaintenanceMarker{}, false
	}
	marker := string(data)
	if !strings.HasSuffix(marker, "\n") || strings.Count(marker, "\n") != 1 {
		return packageMaintenanceMarker{}, false
	}
	fields := strings.Fields(strings.TrimSuffix(marker, "\n"))
	if len(fields) != 3 || marker != fields[0]+" "+fields[1]+" "+fields[2]+"\n" {
		return packageMaintenanceMarker{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 1 || strconv.Itoa(pid) != fields[0] {
		return packageMaintenanceMarker{}, false
	}
	startTime, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil || startTime == 0 || strconv.FormatUint(startTime, 10) != fields[2] {
		return packageMaintenanceMarker{}, false
	}
	return packageMaintenanceMarker{pid: pid, bootID: fields[1], startTime: startTime}, true
}
