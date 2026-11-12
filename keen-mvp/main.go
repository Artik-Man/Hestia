// Package main provides a small Entware package that keeps one NDM OpkgTun object available to Hestia.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	ndmName      = "OpkgTun0"
	ownerPath    = "/opt/var/lib/keen-mvp/opkgtun0.owner"
	ndmAddress   = "172.31.250.1"
	ndmNetmask   = "255.255.255.255"
	interfaceMTU = "1500"
)

// main dispatches the supported foreground and status commands and reports failures to stderr.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: keen-mvp run|status|cleanup")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = run()
	case "status":
		err = status()
	case "cleanup":
		err = removeNDMInterface()
	default:
		err = errors.New("unknown command")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "keen-mvp:", err)
		os.Exit(1)
	}
}

// run creates or reuses the package-owned NDM object and leaves its TUN device available for the Hestia process.
func run() error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if _, err := ensureNDMInterface(); err != nil {
		return err
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	signal.Stop(stop)
	return removeNDMInterface()
}

// status confirms the NDM object is package-owned and ready for Hestia to attach its TUN file descriptor.
func status() error {
	owned, err := ownsNDMInterface()
	if err != nil || !owned {
		return errors.New("interface is not owned by this package")
	}
	present, err := ndmInterfacePresent()
	if err != nil {
		return err
	}
	if !present {
		return errors.New("NDM interface is absent")
	}
	fmt.Println(ndmName, "is present; TUN is available for Hestia")
	return nil
}

// ensureNDMInterface refuses unowned objects and configures only the fixed interface name.
func ensureNDMInterface() (bool, error) {
	present, err := ndmInterfacePresent()
	if err != nil {
		return false, err
	}
	owned := false
	created := false
	if present {
		isOwned, ownerErr := ownsNDMInterface()
		if ownerErr != nil || !isOwned {
			return false, errors.New("OpkgTun0 already exists and is not owned by keen-mvp")
		}
		owned = true
	} else {
		if err := ndm("interface " + ndmName); err != nil {
			return false, fmt.Errorf("create NDM interface: %w", err)
		}
		if err := writeOwnerMarker(); err != nil {
			_ = ndm("no interface " + ndmName)
			return false, err
		}
		owned = true
		created = true
	}
	commands := []string{
		"interface " + ndmName + " description Keen-MVP",
		"interface " + ndmName + " ip global auto",
		"interface " + ndmName + " ip address " + ndmAddress + " " + ndmNetmask,
		"interface " + ndmName + " ip mtu " + interfaceMTU,
		"interface " + ndmName + " ip tcp adjust-mss pmtu",
		"interface " + ndmName + " up",
	}
	for _, command := range commands {
		if err := ndm(command); err != nil {
			if created {
				_ = removeNDMInterface()
			}
			return owned, fmt.Errorf("configure NDM interface: %w", err)
		}
	}
	return owned, nil
}

// ndmInterfacePresent uses the read-only NDM interface listing and matches only the exact object name.
func ndmInterfacePresent() (bool, error) {
	output, err := runNDM("show interface")
	if err != nil {
		return false, errors.New("cannot read NDM interface list")
	}
	for _, field := range strings.FieldsFunc(output, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) {
		if strings.EqualFold(field, ndmName) {
			return true, nil
		}
	}
	return false, nil
}

// ndm executes one fixed NDM configuration command without invoking a shell.
func ndm(command string) error {
	_, err := runNDM(command)
	return err
}

// runNDM invokes ndmc and returns its output only to the caller, never logging router configuration.
func runNDM(command string) (string, error) {
	path, err := execLookPath("ndmc")
	if err != nil {
		return "", errors.New("ndmc executable is unavailable")
	}
	return commandOutput(path, command)
}

// execLookPath resolves a required program using the Entware init environment's PATH.
func execLookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// commandOutput runs a single fixed-argument command and returns output only for local parsing.
func commandOutput(path string, command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "-c", command).CombinedOutput()
	if err != nil {
		return "", errors.New("ndmc command failed")
	}
	return string(output), nil
}

// writeOwnerMarker creates a root-only persistent marker after this package creates the NDM object.
func writeOwnerMarker() error {
	if err := os.MkdirAll(filepath.Dir(ownerPath), 0o750); err != nil {
		return fmt.Errorf("create owner state directory: %w", err)
	}
	file, err := os.OpenFile(ownerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create owner marker: %w", err)
	}
	if _, err := file.WriteString(ndmName + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(ownerPath)
		return fmt.Errorf("write owner marker: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(ownerPath)
		return fmt.Errorf("close owner marker: %w", err)
	}
	return nil
}

// ownsNDMInterface validates the exact root-only marker before allowing this package to change NDM state.
func ownsNDMInterface() (bool, error) {
	info, err := os.Lstat(ownerPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, errors.New("owner marker has unsafe file type or permissions")
	}
	content, err := os.ReadFile(ownerPath)
	if err != nil {
		return false, err
	}
	return string(content) == ndmName+"\n", nil
}

// removeNDMInterface deletes only the exact NDM object recorded as owned by this package.
func removeNDMInterface() error {
	owned, err := ownsNDMInterface()
	if err != nil {
		return fmt.Errorf("validate owner marker: %w", err)
	}
	if !owned {
		return nil
	}
	if err := ndm("no interface " + ndmName); err != nil {
		return fmt.Errorf("remove NDM interface: %w", err)
	}
	if err := os.Remove(ownerPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove owner marker: %w", err)
	}
	return nil
}
