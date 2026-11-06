// Package keeneticdiagnostics provides bounded, read-only environment inventory.
// It does not establish hardware compatibility or execute any detected program.
package keeneticdiagnostics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
)

// observationStatus distinguishes a missing inventory item from a failed observation.
type observationStatus string

const (
	statusPresent     observationStatus = "present"
	statusAbsent      observationStatus = "absent"
	statusError       observationStatus = "error"
	statusNotTested   observationStatus = "not_tested"
	statusUnsupported observationStatus = "unsupported"
)

// valueObservation exposes only a validated kernel release, without raw read errors.
type valueObservation struct {
	Status observationStatus `json:"status"`
	Value  string            `json:"value,omitempty"`
}

// memoryObservation contains only explicitly allowed numeric memory measurements.
type memoryObservation struct {
	Status    observationStatus `json:"status"`
	ValuesKiB map[string]uint64 `json:"values_kib,omitempty"`
}

// pathObservation distinguishes object presence and type without asserting usability.
type pathObservation struct {
	Status observationStatus `json:"status"`
	Kind   string            `json:"kind,omitempty"`
}

// inventoryReport is the versioned output contract; capability assertions are never inferred from presence.
type inventoryReport struct {
	SchemaVersion  int                          `json:"schema_version"`
	BuildVersion   string                       `json:"build_version"`
	OS             string                       `json:"os"`
	Architecture   string                       `json:"architecture"`
	PlatformStatus observationStatus            `json:"platform_status"`
	Kernel         valueObservation             `json:"kernel_release"`
	Memory         memoryObservation            `json:"memory"`
	Paths          map[string]pathObservation   `json:"paths"`
	Utilities      map[string]observationStatus `json:"utilities"`
	Capabilities   map[string]observationStatus `json:"capabilities"`
	Limitations    []string                     `json:"limitations"`
}

var kernelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}$`)

// Run accepts only explicit inventory, help, or version requests and writes solely to the supplied streams.
// The caller provides a read-only filesystem rooted at / and runtime OS/architecture.
// Exit 2 denotes invalid arguments, exit 1 output failure, and exit 0 a report (which may contain observation errors).
func Run(args []string, stdout, stderr io.Writer, sources fs.FS, goos, goarch, version string) int {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, err := fmt.Fprintln(stdout, "Диагностика Keenetic: --inventory (JSON), --version, --help.\nТолько чтение среды; сетевые возможности не проверяются.")
		if err != nil {
			return 1
		}
		return 0
	}
	if len(args) == 1 && args[0] == "--version" {
		_, err := fmt.Fprintln(stdout, version)
		if err != nil {
			return 1
		}
		return 0
	}
	if len(args) != 1 || args[0] != "--inventory" {
		fmt.Fprintln(stderr, "Неверные аргументы. Используйте --help или явный --inventory.")
		return 2
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(collectInventory(sources, goos, goarch, version)); err != nil {
		fmt.Fprintln(stderr, "Не удалось записать отчёт.")
		return 1
	}
	return 0
}

// collectInventory reads a fixed allowlist on Linux ARM64 and labels every functional capability untested.
func collectInventory(sources fs.FS, goos, goarch, version string) inventoryReport {
	report := inventoryReport{SchemaVersion: 1, BuildVersion: version, OS: goos, Architecture: goarch,
		PlatformStatus: statusUnsupported, Kernel: valueObservation{Status: statusNotTested}, Memory: memoryObservation{Status: statusNotTested},
		Paths: map[string]pathObservation{}, Utilities: map[string]observationStatus{}, Capabilities: map[string]observationStatus{},
		Limitations: []string{"Инвентаризация не подтверждает модель роутера, версию KeeneticOS или совместимость Hestia.", "Наличие файла или программы не подтверждает работоспособность, права или версию.", "Программы не запускаются; сеть, службы и файлы не изменяются.", "Свободное место /opt и версии runtime требуют отдельной проверки."}}
	for _, capability := range []string{"tun", "netns_veth", "policy_routing", "packet_marks", "fail_closed", "netfilter", "wisp", "cli_rci", "hardware_acceleration", "vpn_runtime", "dns_ipv6", "event_recovery", "opt_persistence"} {
		report.Capabilities[capability] = statusNotTested
	}
	if goos != "linux" || goarch != "arm64" {
		return report
	}
	report.PlatformStatus = statusPresent
	report.Kernel = readKernel(sources)
	report.Memory = readMemory(sources)
	for _, name := range []string{"opt", "dev/net/tun"} {
		report.Paths["/"+name] = observePath(sources, name)
	}
	for _, name := range []string{"ip", "iptables", "ip6tables", "nft", "ndmq", "opkg", "sing-box", "amneziawg-go", "awg", "sstpc", "pppd"} {
		report.Utilities[name] = observeUtility(sources, name)
	}
	return report
}

// readLimited rejects oversized sources and returns only classified errors, never file contents on failure.
func readLimited(sources fs.FS, name string, maximum int64) ([]byte, observationStatus) {
	file, err := sources.Open(name)
	if err != nil {
		return nil, classifyError(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, statusError
	}
	return data, statusPresent
}

// classifyError distinguishes absence from all other failures without leaking filesystem error text.
func classifyError(err error) observationStatus {
	if errors.Is(err, fs.ErrNotExist) {
		return statusAbsent
	}
	return statusError
}

// readKernel accepts only a short kernel release token from the fixed proc source.
func readKernel(sources fs.FS) valueObservation {
	data, status := readLimited(sources, "proc/sys/kernel/osrelease", 256)
	if status != statusPresent {
		return valueObservation{Status: status}
	}
	value := strings.TrimSpace(string(data))
	if !kernelPattern.MatchString(value) {
		return valueObservation{Status: statusError}
	}
	return valueObservation{Status: statusPresent, Value: value}
}

// readMemory exports only numeric kB fields and rejects malformed allowed fields without exposing their contents.
func readMemory(sources fs.FS) memoryObservation {
	data, status := readLimited(sources, "proc/meminfo", 65536)
	if status != statusPresent {
		return memoryObservation{Status: status}
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || (name != "MemTotal" && name != "MemAvailable" && name != "MemFree" && name != "SwapTotal" && name != "SwapFree") {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return memoryObservation{Status: statusError}
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return memoryObservation{Status: statusError}
		}
		if _, exists := values[name]; exists {
			return memoryObservation{Status: statusError}
		}
		values[name] = value
	}
	if _, exists := values["MemTotal"]; !exists {
		return memoryObservation{Status: statusError}
	}
	return memoryObservation{Status: statusPresent, ValuesKiB: values}
}

// observePath reports metadata for a fixed path without opening device contents or enumerating directories.
func observePath(sources fs.FS, name string) pathObservation {
	info, err := fs.Stat(sources, name)
	if err != nil {
		return pathObservation{Status: classifyError(err)}
	}
	kind := "other"
	switch {
	case info.IsDir():
		kind = "directory"
	case info.Mode()&fs.ModeCharDevice != 0:
		kind = "character_device"
	case info.Mode().IsRegular():
		kind = "regular_file"
	}
	return pathObservation{Status: statusPresent, Kind: kind}
}

// observeUtility checks fixed system directories, ignores PATH, and never runs the detected file.
func observeUtility(sources fs.FS, name string) observationStatus {
	result := statusAbsent
	for _, directory := range []string{"opt/bin", "opt/sbin", "usr/bin", "usr/sbin", "bin", "sbin"} {
		info, err := fs.Stat(sources, directory+"/"+name)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				result = statusError
			}
			continue
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return statusPresent
		}
	}
	return result
}
