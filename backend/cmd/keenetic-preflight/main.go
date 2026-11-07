// Command keenetic-preflight verifies the target and local install conditions before IPK extraction.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const tokenPath = "/opt/etc/hestia/keenetic-rci-token"

// main fails closed unless this process runs as root on the observed KN-1012 firmware with a usable /opt.
func main() {
	if err := verify(); err != nil {
		fmt.Fprintln(os.Stderr, "Hestia target preflight failed; no package files were extracted")
		os.Exit(1)
	}
	fmt.Println("Hestia target preflight passed")
}

// verify checks process privileges, kernel architecture, authenticated RCI identity, Entware and /opt capacity.
func verify() error {
	if os.Geteuid() != 0 {
		return errors.New("root required")
	}
	if err := verifyArchitecture(); err != nil {
		return err
	}
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL:     "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{Path: tokenPath},
		Timeout:     3 * time.Second,
	})
	if err != nil {
		return err
	}
	version, err := client.ReadVersion(context.Background())
	if err != nil {
		return err
	}
	if version.Model != "Giga (KN-1012)" || version.Title != "5.2 Beta 3" || version.Release != "5.02.B.3.0-2" || version.Architecture != "aarch64" {
		return errors.New("unsupported router version")
	}
	return verifyOptCapacity(512 * 1024 * 1024)
}

// verifyArchitecture requires the AArch64 Linux userspace declared by this package.
func verifyArchitecture() error {
	if strings.TrimSpace(string(mustOutput("/opt/bin/busybox", "uname", "-m"))) != "aarch64" {
		return errors.New("unsupported architecture")
	}
	return nil
}

// mustOutput returns bounded utility output and hides utility details from preflight diagnostics.
func mustOutput(path string, arguments ...string) []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"PATH=/opt/bin:/bin:/usr/bin", "LC_ALL=C"}
	output, err := command.Output()
	if err != nil || len(output) > 4096 {
		return nil
	}
	return output
}

// verifyOptCapacity requires protected root-owned /opt and the install reserve to be available.
func verifyOptCapacity(minimumBytes uint64) error {
	info, err := os.Lstat("/opt")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !ownedByRoot(info) {
		return errors.New("unsafe opt directory")
	}
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs("/opt", &filesystem); err != nil || uint64(filesystem.Bavail)*uint64(filesystem.Bsize) < minimumBytes {
		return errors.New("insufficient opt capacity")
	}
	for _, directory := range []string{"/opt/etc", "/opt/etc/hestia"} {
		parent, err := os.Lstat(directory)
		if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0o022 != 0 || !ownedByRoot(parent) {
			return errors.New("unsafe token directory")
		}
	}
	return nil
}

// ownedByRoot checks a filesystem object's numeric owner without following symbolic links.
func ownedByRoot(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}
