package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"runtime"

	"github.com/Artik-Man/Hestia/internal/routing"
)

// groupLock reserves one selector's writer in the Linux network namespace hosting its management API.
func groupLock(group string) (net.Listener, error) {
	return net.Listen("unix", fmt.Sprintf("@hestia-guard-%x", sha256.Sum256([]byte(group))))
}

// ownedReconcile prevents a snapshot writer from overwriting a Linux selector owned by a balance or guard command.
func ownedReconcile(ctx context.Context, client *http.Client, base string, group routing.Group, target string) (bool, error) {
	if runtime.GOOS == "linux" {
		lock, err := groupLock(group.ID)
		if err != nil {
			return false, fmt.Errorf("reserve selector %s: %w", group.ID, err)
		}
		defer lock.Close()
	}
	return reconcile(ctx, client, base, group, target)
}
