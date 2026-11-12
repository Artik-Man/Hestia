//go:build linux

package entware

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const maxCommandLineSize = 1 << 20
const managedRoleEnvironment = "HESTIA_MANAGED_SERVICE="

// CheckManagedProcessesStopped succeeds only when /proc contains no Hestia service process.
func CheckManagedProcessesStopped() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return errors.New("cannot inspect managed process state")
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		state, err := readProcessState(pid)
		if errors.Is(err, os.ErrNotExist) {
			if processHasExited(pid) {
				continue
			}
		}
		if err != nil {
			return errors.New("cannot verify managed process state")
		}
		if state == 'Z' || state == 'X' {
			continue
		}
		arguments, err := readProcessArguments(pid)
		if errors.Is(err, os.ErrNotExist) {
			if processHasExited(pid) {
				continue
			}
		}
		if err != nil {
			return errors.New("cannot verify managed process state")
		}
		executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if errors.Is(err, os.ErrNotExist) {
			if processHasExited(pid) || isKernelThread(pid) {
				continue
			}
		}
		if err != nil {
			return errors.New("cannot verify managed process executable")
		}
		var environment []string
		var mappings []string
		if executable == "/opt/lib/ld-linux-aarch64.so.1" || isManagedGoExecutable(executable) {
			environment, err = readProcessEnvironment(pid)
			if errors.Is(err, os.ErrNotExist) {
				if processHasExited(pid) {
					continue
				}
			}
			if err != nil {
				return errors.New("cannot verify managed process environment")
			}
			if executable == "/opt/lib/ld-linux-aarch64.so.1" {
				mappings, err = readProcessMappings(pid)
				if errors.Is(err, os.ErrNotExist) {
					if processHasExited(pid) {
						continue
					}
				}
				if err != nil {
					return errors.New("cannot verify managed process mappings")
				}
			}
		}
		if isManagedProcess(arguments, executable, environment, mappings) {
			return errors.New("managed Hestia process remains active")
		}
	}
	return nil
}

// processHasExited confirms that a proc metadata read raced with removal of the process directory.
func processHasExited(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return errors.Is(err, os.ErrNotExist)
}

// isKernelThread checks PF_KTHREAD in proc stat before allowing a live task without an executable link.
func isKernelThread(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	closingParenthesis := strings.LastIndexByte(string(data), ')')
	if closingParenthesis < 0 {
		return false
	}
	fields := strings.Fields(string(data[closingParenthesis+1:]))
	if len(fields) <= 6 {
		return false
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	return err == nil && flags&0x00200000 != 0
}

// CheckSupervisorProcess verifies that pid is the exact Hestia supervisor executable and invocation.
func CheckSupervisorProcess(pid int) error {
	if pid <= 0 {
		return errors.New("invalid supervisor PID")
	}
	arguments, err := readProcessArguments(pid)
	if err != nil || len(arguments) != 2 || arguments[0] != "/opt/bin/hestia" || arguments[1] != "-service-supervisor" {
		return errors.New("Hestia supervisor is not running with the recorded PID")
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || executable != "/opt/bin/hestia" {
		return errors.New("Hestia supervisor executable does not match the recorded PID")
	}
	return nil
}

// readProcessState returns the Linux process state code from /proc status.
func readProcessState(pid int) (byte, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "State:" && len(fields[1]) == 1 {
			return fields[1][0], nil
		}
	}
	return 0, errors.New("process state is missing")
}

// readProcessArguments reads one bounded NUL-separated proc command line.
func readProcessArguments(pid int) ([]string, error) {
	data, err := readBoundedProcessFile(pid, "cmdline")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	parts := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	return parts, nil
}

// readProcessEnvironment reads bounded NUL-separated environment entries without returning their values to logs.
func readProcessEnvironment(pid int) ([]string, error) {
	data, err := readBoundedProcessFile(pid, "environ")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(strings.TrimRight(string(data), "\x00"), "\x00"), nil
}

// readProcessMappings returns bounded proc maps to identify the actual dynamically loaded router executable.
func readProcessMappings(pid int) ([]string, error) {
	data, err := readBoundedProcessFile(pid, "maps")
	if err != nil {
		return nil, err
	}
	return strings.Split(string(data), "\n"), nil
}

// readBoundedProcessFile reads a process metadata file without allocating beyond the configured limit.
func readBoundedProcessFile(pid int, name string) ([]byte, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxCommandLineSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCommandLineSize {
		return nil, errors.New("process metadata is invalid")
	}
	return data, nil
}

// isManagedGoExecutable recognizes Hestia Go binaries before or after package replacement.
func isManagedGoExecutable(executable string) bool {
	for _, path := range []string{"/opt/bin/hestia", "/opt/bin/hestia-panel", "/opt/bin/amneziawg-go"} {
		if executable == path || executable == path+" (deleted)" {
			return true
		}
	}
	return false
}

// isManagedProcess identifies Hestia by executable path, exact service argv, or a fixed service role marker.
func isManagedProcess(arguments []string, executable string, environment, mappings []string) bool {
	if executable == "/opt/bin/hestia" || executable == "/opt/bin/hestia-panel" {
		return true
	}
	if len(arguments) > 4 && arguments[0] == "/opt/lib/ld-linux-aarch64.so.1" &&
		arguments[3] == "/opt/lib/hestia/sing-box" && arguments[4] == "run" {
		return true
	}
	if executable == "/opt/lib/ld-linux-aarch64.so.1" {
		for _, line := range mappings {
			fields := strings.Fields(line)
			if len(fields) >= 6 && strings.Contains(fields[1], "x") && fields[5] == "/opt/lib/hestia/sing-box" {
				return true
			}
		}
	}
	for _, value := range environment {
		if strings.HasPrefix(value, managedRoleEnvironment) {
			switch strings.TrimPrefix(value, managedRoleEnvironment) {
			case "router", "controller", "panel", "binding-watch", "awg":
				return true
			}
		}
	}
	return false
}
