//go:build linux

// Package main runs a bounded AmneziaWG userspace daemon with private resources.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	tunSetIFF  = 0x400454ca
	iffTUN     = 0x0001
	iffNoPI    = 0x1000
	iffTunExcl = 0x8000
)

// main creates an exclusive TUN and private UAPI listener, runs one daemon, and reports only redacted results.
func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: probe <runtime-dir> <interface-name> <daemon-path>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "probe_error=%v\n", err)
		os.Exit(1)
	}
}

// run owns a private runtime directory and bounds the daemon lifetime to this invocation.
func run(runtimeDir, interfaceName, daemonPath string) (result error) {
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("create private directory: %w", err)
	}
	defer func() {
		if err := removeOwnedSocket(filepath.Join(runtimeDir, interfaceName+".sock")); err != nil {
			result = errors.Join(result, err)
		}
		if err := os.Remove(runtimeDir); err != nil {
			result = errors.Join(result, fmt.Errorf("remove own runtime directory: %w", err))
		} else {
			fmt.Println("runtime_directory_removed=true")
		}
	}()

	tunFile, err := openExclusiveTun(interfaceName)
	if err != nil {
		return err
	}
	defer tunFile.Close()
	fmt.Printf("tun_created=true interface=%s\n", interfaceName)
	if err := printInterfaceFlags(interfaceName, "before_daemon"); err != nil {
		return err
	}

	socketPath := filepath.Join(runtimeDir, interfaceName+".sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("create private UAPI listener: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	listenerFile, err := listener.File()
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("duplicate private UAPI listener: %w", err)
	}
	if err := listener.Close(); err != nil {
		_ = listenerFile.Close()
		return fmt.Errorf("close parent listener: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, daemonPath, "-f", interfaceName)
	cmd.ExtraFiles = []*os.File{tunFile, listenerFile}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "WG_TUN_FD=3", "WG_UAPI_FD=4", "WG_PROCESS_FOREGROUND=1", "LOG_LEVEL=error")
	if err := cmd.Start(); err != nil {
		_ = listenerFile.Close()
		return fmt.Errorf("start pinned daemon: %w", err)
	}
	_ = tunFile.Close()
	_ = listenerFile.Close()
	fmt.Printf("daemon_started=true pid=%d\n", cmd.Process.Pid)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			if err := waitForProcess(done, 4*time.Second); err != nil {
				_ = cmd.Process.Kill()
				_ = waitForProcess(done, time.Second)
			}
		}
	}()

	if err := waitForSocket(socketPath, done, 3*time.Second); err != nil {
		return err
	}
	fmt.Println("private_uapi_ready=true")
	if err := printInterfaceFlags(interfaceName, "daemon_running"); err != nil {
		return err
	}
	if err := exerciseUAPI(socketPath); err != nil {
		return err
	}
	if err := printInterfaceFlags(interfaceName, "after_uapi"); err != nil {
		return err
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("terminate owned daemon: %w", err)
	}
	if err := waitForProcess(done, 4*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = waitForProcess(done, time.Second)
		stopped = true
		return err
	}
	stopped = true
	fmt.Println("daemon_exit=0")
	if _, err := os.Stat(filepath.Join("/sys/class/net", interfaceName)); !os.IsNotExist(err) {
		return fmt.Errorf("TUN remains after daemon exit and local descriptor close: stat_error=%v", err)
	}
	fmt.Println("interface_absent_after_daemon_exit=true")
	return nil
}

// openExclusiveTun creates only a new named TUN and refuses to attach to an existing interface.
func openExclusiveTun(name string) (*os.File, error) {
	if len(name) == 0 || len(name) >= 16 || strings.ContainsRune(name, '/') {
		return nil, fmt.Errorf("invalid interface name %q", name)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open TUN device: %w", err)
	}
	var request [40]byte
	copy(request[:16], name)
	*(*uint16)(unsafe.Pointer(&request[16])) = iffTUN | iffNoPI | iffTunExcl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), tunSetIFF, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("TUNSETIFF(IFF_TUN|IFF_NO_PI|IFF_TUN_EXCL): %w", errno)
	}
	return file, nil
}

// waitForSocket waits for the daemon's UAPI listener without sending any request to a shared path.
func waitForSocket(path string, done chan error, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case waitErr := <-done:
			done <- waitErr
			return fmt.Errorf("daemon exited before UAPI readiness: %v", waitErr)
		default:
		}
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("private UAPI did not become ready within %s", timeout)
}

// exerciseUAPI sets one generated ephemeral key and verifies its private get/readback response without logging key material.
func exerciseUAPI(path string) error {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return fmt.Errorf("generate ephemeral synthetic key: %w", err)
	}
	defer clear(privateKey)
	expectedPublic, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("derive expected synthetic public key: %w", err)
	}
	setRequest := "set=1\nprivate_key=" + hex.EncodeToString(privateKey) + "\n\n"
	setResponse, err := uapiRequest(path, setRequest)
	if err != nil {
		return fmt.Errorf("UAPI set: %w", err)
	}
	setErrno, err := parseErrno(setResponse)
	if err != nil || setErrno != 0 {
		return fmt.Errorf("UAPI set errno=%d parse_error=%v", setErrno, err)
	}
	fmt.Printf("uapi_set_errno=%d\n", setErrno)

	getResponse, err := uapiRequest(path, "get=1\n\n")
	if err != nil {
		return fmt.Errorf("UAPI get: %w", err)
	}
	getErrno, err := parseErrno(getResponse)
	if err != nil || getErrno != 0 {
		return fmt.Errorf("UAPI get errno=%d parse_error=%v", getErrno, err)
	}
	returnedPrivate, peers, err := parseGet(getResponse)
	if err != nil {
		return err
	}
	defer clear(returnedPrivate)
	returnedPublic, err := ecdh.X25519().NewPrivateKey(returnedPrivate)
	if err != nil {
		return fmt.Errorf("derive readback public key: %w", err)
	}
	zeroKey := make([]byte, 32)
	returnedKeyNonzero := subtle.ConstantTimeCompare(returnedPrivate, zeroKey) != 1
	publicDerivationMatch := bytes.Equal(expectedPublic.PublicKey().Bytes(), returnedPublic.PublicKey().Bytes())
	fmt.Printf("uapi_get_errno=%d peers=%d returned_key_nonzero=%t synthetic_public_derivation_match=%t\n", getErrno, peers, returnedKeyNonzero, publicDerivationMatch)
	if !returnedKeyNonzero || !publicDerivationMatch || peers != 0 {
		return errors.New("UAPI synthetic public derivation or empty-peer invariant failed")
	}
	return nil
}

// uapiRequest exchanges one bounded request with the private Unix socket and returns its in-memory response.
func uapiRequest(path, request string) (string, error) {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", err
	}
	var response strings.Builder
	buffer := make([]byte, 4096)
	for response.Len() < 1<<16 {
		n, readErr := conn.Read(buffer)
		if n > 0 {
			response.Write(buffer[:n])
			if strings.HasSuffix(response.String(), "\n\n") {
				return response.String(), nil
			}
		}
		if readErr != nil {
			return "", readErr
		}
	}
	return "", errors.New("UAPI response exceeded 65536 bytes")
}

// parseErrno extracts only the status code from a UAPI response.
func parseErrno(response string) (int, error) {
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(line, "errno=") {
			return strconv.Atoi(strings.TrimPrefix(line, "errno="))
		}
	}
	return -1, errors.New("missing errno field")
}

// parseGet extracts the ephemeral device key and counts peers without emitting response contents.
func parseGet(response string) ([]byte, int, error) {
	var privateKey []byte
	peers := 0
	for _, line := range strings.Split(response, "\n") {
		if strings.HasPrefix(line, "private_key=") {
			value := strings.TrimPrefix(line, "private_key=")
			decoded, err := hex.DecodeString(value)
			if err != nil {
				return nil, peers, fmt.Errorf("decode UAPI private-key readback: %w", err)
			}
			privateKey = decoded
		}
		if strings.HasPrefix(line, "public_key=") {
			peers++
		}
	}
	if len(privateKey) != 32 {
		clear(privateKey)
		return nil, peers, fmt.Errorf("UAPI readback key length=%d, expected 32", len(privateKey))
	}
	return privateKey, peers, nil
}

// printInterfaceFlags reports the interface flags and rejects an interface that became administratively up.
func printInterfaceFlags(name, phase string) error {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", name, "flags"))
	if err != nil {
		return fmt.Errorf("read %s TUN flags: %w", phase, err)
	}
	flags, err := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 32)
	if err != nil {
		return fmt.Errorf("parse %s TUN flags: %w", phase, err)
	}
	fmt.Printf("interface_phase=%s flags=0x%x up=%t\n", phase, flags, flags&1 != 0)
	if flags&1 != 0 {
		return fmt.Errorf("TUN %s unexpectedly has IFF_UP set", phase)
	}
	return nil
}

// waitForProcess waits for the one owned daemon to exit within a fixed bound and preserves its result for cleanup.
func waitForProcess(done chan error, timeout time.Duration) error {
	select {
	case err := <-done:
		done <- err
		if err != nil {
			return fmt.Errorf("daemon wait: %w", err)
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("daemon did not exit within %s", timeout)
	}
}

// removeOwnedSocket unlinks only the private socket path created by this probe after the daemon has exited.
func removeOwnedSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		fmt.Println("private_uapi_socket_removed=true")
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect own UAPI socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refuse to remove non-socket at own UAPI path: %s", info.Mode())
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove own UAPI socket: %w", err)
	}
	fmt.Println("private_uapi_socket_removed=true")
	return nil
}
