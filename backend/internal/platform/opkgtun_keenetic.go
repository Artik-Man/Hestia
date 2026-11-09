//go:build keenetic

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/services/entware"
	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const (
	opkgTunName      = "OpkgTun0"
	opkgTunOwnerPath = "/opt/var/lib/hestia/opkgtun0.owner"
	opkgTunAddress   = "172.31.250.1"
	opkgTunNetmask   = "255.255.255.255"
	opkgTunMTU       = "1500"
)

// EnsureOpkgTun creates and configures Hestia's visible NDM OpkgTun without enabling it as the router default gateway.
func EnsureOpkgTun() error {
	if os.Geteuid() != 0 {
		return errors.New("OpkgTun lifecycle requires root")
	}
	if err := secureOpkgTunDirectory(filepath.Dir(opkgTunOwnerPath)); err != nil {
		return err
	}
	owned, ownerErr := opkgTunOwned()
	if ownerErr != nil {
		return errors.New("Hestia OpkgTun ownership marker is unsafe")
	}
	present, err := opkgTunPresent()
	if err != nil {
		return err
	}
	created := false
	if present {
		if !owned {
			return errors.New("OpkgTun0 exists and is not owned by Hestia")
		}
	} else {
		if err := runNDM("interface " + opkgTunName); err != nil {
			return fmt.Errorf("create Hestia OpkgTun: %w", err)
		}
		created = true
		if !owned {
			if err := writeOpkgTunOwner(); err != nil {
				_ = runNDM("no interface " + opkgTunName)
				return err
			}
		}
	}
	for _, command := range []string{
		"interface " + opkgTunName + " description Hestia",
		"interface " + opkgTunName + " ip global auto",
		"interface " + opkgTunName + " ip address " + opkgTunAddress + " " + opkgTunNetmask,
		"interface " + opkgTunName + " ip mtu " + opkgTunMTU,
		"interface " + opkgTunName + " ip tcp adjust-mss pmtu",
		"interface " + opkgTunName + " up",
	} {
		if err := runNDM(command); err != nil {
			if created {
				_ = removeOwnedOpkgTun()
			}
			return fmt.Errorf("configure Hestia OpkgTun: %w", err)
		}
	}
	return nil
}

// RemoveOpkgTun removes only the NDM object whose root-only ownership marker belongs to Hestia.
func RemoveOpkgTun() error {
	if os.Geteuid() != 0 {
		return errors.New("OpkgTun lifecycle requires root")
	}
	if err := entware.CheckManagedProcessesStopped(); err != nil {
		return errors.New("cannot remove OpkgTun while Hestia services may be running")
	}
	if err := ensureOpkgTunUnusedByPolicies(); err != nil {
		return err
	}
	return removeOwnedOpkgTun()
}

// ensureOpkgTunUnusedByPolicies requires a complete read-only RCI snapshot proving no policy selects Hestia OpkgTun.
func ensureOpkgTunUnusedByPolicies() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: 3 * time.Second,
	})
	if err != nil {
		return errors.New("cannot verify that no Keenetic policy uses OpkgTun0")
	}
	policies, err := client.ReadIPPolicies(ctx)
	if err != nil {
		return errors.New("cannot verify that no Keenetic policy uses OpkgTun0")
	}
	for _, policy := range policies {
		if slices.Contains(policy.OpkgTunInterfaces, opkgTunName) {
			return errors.New("remove OpkgTun0 from every Keenetic policy before removing Hestia")
		}
	}
	return nil
}

// removeOwnedOpkgTun verifies ownership before deleting the fixed NDM interface and marker.
func removeOwnedOpkgTun() error {
	if err := secureOpkgTunDirectory(filepath.Dir(opkgTunOwnerPath)); err != nil {
		return err
	}
	owned, err := opkgTunOwned()
	if err != nil || !owned {
		return err
	}
	present, err := opkgTunPresent()
	if err != nil {
		return err
	}
	if present {
		if err := runNDM("no interface " + opkgTunName); err != nil {
			return fmt.Errorf("remove Hestia OpkgTun: %w", err)
		}
	}
	if err := os.Remove(opkgTunOwnerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove Hestia OpkgTun ownership marker")
	}
	return nil
}

// opkgTunPresent matches only the exact managed object in NDM's read-only interface listing.
func opkgTunPresent() (bool, error) {
	output, err := runNDMOutput("show interface")
	if err != nil {
		return false, errors.New("cannot read NDM interface list")
	}
	for _, field := range strings.FieldsFunc(output, func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) {
		if strings.EqualFold(field, opkgTunName) {
			return true, nil
		}
	}
	return false, nil
}

// opkgTunOwned validates a root-owned, single-link marker with the exact Hestia interface identity.
func opkgTunOwned() (bool, error) {
	info, err := os.Lstat(opkgTunOwnerPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Nlink != 1 || info.Size() > 64 {
		return false, errors.New("Hestia OpkgTun ownership marker is unsafe")
	}
	content, err := os.ReadFile(opkgTunOwnerPath)
	if err != nil {
		return false, err
	}
	return string(content) == opkgTunName+"\n", nil
}

// writeOpkgTunOwner writes a private marker after Hestia creates the NDM interface.
func writeOpkgTunOwner() error {
	directory := filepath.Dir(opkgTunOwnerPath)
	if err := secureOpkgTunDirectory(directory); err != nil {
		return err
	}
	file, err := os.OpenFile(opkgTunOwnerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return errors.New("create Hestia OpkgTun ownership marker")
	}
	if _, err := file.WriteString(opkgTunName + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(opkgTunOwnerPath)
		return errors.New("write Hestia OpkgTun ownership marker")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(opkgTunOwnerPath)
		return errors.New("close Hestia OpkgTun ownership marker")
	}
	return nil
}

// secureOpkgTunDirectory creates and verifies the private Hestia state directory without following symlinks.
func secureOpkgTunDirectory(path string) error {
	if err := secureOpkgRoot(); err != nil {
		return err
	}
	for _, item := range []string{"/opt/var", "/opt/var/lib", filepath.Dir(path)} {
		info, err := os.Lstat(item)
		if errors.Is(err, os.ErrNotExist) {
			mode := os.FileMode(0o755)
			if item == filepath.Dir(path) {
				mode = 0o700
			}
			if err := os.Mkdir(item, mode); err != nil && !errors.Is(err, os.ErrExist) {
				return errors.New("create Hestia OpkgTun state directory")
			}
			info, err = os.Lstat(item)
		}
		if err != nil {
			return errors.New("inspect Hestia OpkgTun state directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 ||
			(item != filepath.Dir(path) && info.Mode().Perm()&0o022 != 0) {
			return errors.New("Hestia OpkgTun state directory is unsafe")
		}
		if item == filepath.Dir(path) && info.Mode().Perm() != 0o700 {
			if err := os.Chmod(item, 0o700); err != nil {
				return errors.New("secure Hestia OpkgTun state directory")
			}
		}
	}
	return nil
}

// secureOpkgRoot validates /opt and its resolved Entware ancestors before marker access.
func secureOpkgRoot() error {
	optInfo, err := os.Lstat("/opt")
	if err != nil {
		return errors.New("inspect Entware root")
	}
	if !optInfo.IsDir() && optInfo.Mode()&os.ModeSymlink == 0 {
		return errors.New("Entware root is not a directory")
	}
	if stat, ok := optInfo.Sys().(*syscall.Stat_t); !ok || stat.Uid != 0 {
		return errors.New("Entware root is not root-owned")
	}
	root, err := filepath.EvalSymlinks("/opt")
	if err != nil || !filepath.IsAbs(root) {
		return errors.New("resolve Entware root")
	}
	for current := filepath.Clean(root); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return errors.New("inspect Entware root ancestor")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 {
			return errors.New("Entware root ancestor is unsafe")
		}
		writable := info.Mode().Perm()&0o022 != 0
		sticky := info.Mode()&os.ModeSticky != 0
		if writable && !sticky {
			return errors.New("Entware root ancestor is writable")
		}
		if current == "/" {
			break
		}
	}
	return nil
}

// runNDM executes one fixed NDM configuration command without a shell and discards router output.
func runNDM(command string) error {
	_, err := runNDMOutput(command)
	return err
}

// runNDMOutput runs a bounded ndmc command and returns output only for local interface-name parsing.
func runNDMOutput(command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ndmc", "-c", command).CombinedOutput()
	if err != nil {
		return "", errors.New("NDM command failed")
	}
	return string(output), nil
}
