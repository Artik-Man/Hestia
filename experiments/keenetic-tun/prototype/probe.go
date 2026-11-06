// Command probe creates and removes one temporary TUN interface for the KN-1012 capability experiment.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	ifNameSize = 16
	ifReqSize  = 40

	iocTunSetIFF = 0x400454ca
	iffTun       = 0x0001
	iffNoPI      = 0x1000
	iffTunExcl   = 0x8000
)

var interfaceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,15}$`)

type result struct {
	Name                        string `json:"name"`
	NameAbsentBefore            bool   `json:"name_absent_before"`
	CreateSucceeded             bool   `json:"create_succeeded"`
	InterfacePresentAfterCreate bool   `json:"interface_present_after_create"`
	CloseSucceeded              bool   `json:"close_succeeded"`
	InterfaceAbsentAfterClose   bool   `json:"interface_absent_after_close"`
	Error                       string `json:"error,omitempty"`
}

// main validates the requested interface name, performs one bounded probe, and emits a JSON result.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe <new-interface-name>")
		os.Exit(2)
	}

	watchdog := time.AfterFunc(10*time.Second, func() {
		fmt.Fprintln(os.Stderr, "watchdog expired after 10 seconds; exiting so the kernel closes the TUN descriptor")
		os.Exit(124)
	})
	out, err := run(os.Args[1])
	watchdog.Stop()
	if err != nil {
		out.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(out); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}

// run refuses an existing interface, atomically creates an exclusive nonpersistent TUN, then closes and verifies it is gone.
func run(name string) (out result, runErr error) {
	out.Name = name
	if !interfaceNamePattern.MatchString(name) {
		return out, fmt.Errorf("interface name %q must contain 1-15 ASCII letters, digits, underscore, or hyphen", name)
	}

	present, err := interfacePresent(name)
	if err != nil {
		return out, fmt.Errorf("check interface before creation: %w", err)
	}
	if present {
		return out, fmt.Errorf("refusing preexisting interface %q", name)
	}
	out.NameAbsentBefore = true

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	created := false
	defer func() {
		closeErr := syscall.Close(fd)
		out.CloseSucceeded = closeErr == nil
		if closeErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close TUN descriptor: %w", closeErr))
			return
		}
		if created {
			stillPresent, checkErr := interfacePresent(name)
			if checkErr != nil {
				runErr = errors.Join(runErr, fmt.Errorf("verify interface after close: %w", checkErr))
				return
			}
			out.InterfaceAbsentAfterClose = !stillPresent
			if stillPresent {
				runErr = errors.Join(runErr, fmt.Errorf("interface %q remains after closing its owned descriptor", name))
			}
		}
	}()

	if err := setIFF(fd, name); err != nil {
		return out, fmt.Errorf("TUNSETIFF for %q: %w", name, err)
	}
	created = true
	out.CreateSucceeded = true

	present, err = interfacePresent(name)
	if err != nil {
		return out, fmt.Errorf("verify interface after creation: %w", err)
	}
	out.InterfacePresentAfterCreate = present
	if !present {
		return out, fmt.Errorf("TUNSETIFF succeeded but interface %q is not visible", name)
	}
	return out, nil
}

// interfacePresent reports whether the host network interface list contains the exact requested name.
func interfacePresent(name string) (bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false, err
	}
	for _, iface := range interfaces {
		if iface.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// setIFF requests an exclusive TUN interface without packet information headers and rejects accidental attachment.
func setIFF(fd int, name string) error {
	var request [ifReqSize]byte
	copy(request[:ifNameSize], name)
	binary.LittleEndian.PutUint16(request[ifNameSize:ifNameSize+2], uint16(iffTun|iffNoPI|iffTunExcl))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(iocTunSetIFF), uintptr(unsafe.Pointer(&request[0])))
	runtime.KeepAlive(&request)
	if errno != 0 {
		return errno
	}
	return nil
}
