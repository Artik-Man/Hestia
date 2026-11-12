//go:build linux && keenetic

package keeneticroute

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maxIngressRuleStateRead = maxIngressRuleStateSize + 1

// readOwnedIngressRules loads the root-only RPDB ownership registry without following symbolic links.
func readOwnedIngressRules(path string) ([]ingressRule, error) {
	if err := validateIngressRuleStateDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot open Hestia ingress rule ownership record")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !validIngressRuleStateFile(info) {
		return nil, errors.New("Hestia ingress rule ownership record metadata is invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxIngressRuleStateRead))
	if err != nil || len(data) > maxIngressRuleStateSize {
		return nil, errors.New("cannot read bounded Hestia ingress rule ownership record")
	}
	return parseIngressRuleRegistry(data)
}

// writeOwnedIngressRules atomically stores only validated Hestia RPDB identities in a private state directory.
func writeOwnedIngressRules(path string, rules []ingressRule) error {
	directory := filepath.Dir(path)
	if err := validateIngressRuleStateDirectory(directory); err != nil {
		return err
	}
	data, err := encodeIngressRuleRegistry(rules)
	if err != nil {
		return err
	}
	if _, err := readOwnedIngressRules(path); err != nil {
		return err
	}
	temporary := filepath.Join(directory, fmt.Sprintf(".rules-%d-%d.tmp", os.Getpid(), syscall.Gettid()))
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot create temporary Hestia ingress rule ownership record")
	}
	keepTemporary := true
	defer func() {
		_ = file.Close()
		if keepTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return errors.New("cannot secure temporary Hestia ingress rule ownership record")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("cannot write temporary Hestia ingress rule ownership record")
	}
	if err := file.Sync(); err != nil {
		return errors.New("cannot sync temporary Hestia ingress rule ownership record")
	}
	if err := file.Close(); err != nil {
		return errors.New("cannot close temporary Hestia ingress rule ownership record")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("cannot atomically publish Hestia ingress rule ownership record")
	}
	keepTemporary = false
	directoryFile, err := os.Open(directory)
	if err != nil {
		return errors.New("cannot open Hestia ingress rule state directory for sync")
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return errors.New("cannot sync Hestia ingress rule state directory")
	}
	return nil
}

// validateIngressRuleStateDirectory requires the final state directory to be private, owned by this process, and non-symlink.
func validateIngressRuleStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("Hestia ingress rule state directory cannot be inspected")
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("Hestia ingress rule state directory metadata is unsafe (dir=%t symlink=%t mode=%04o)", info.IsDir(), info.Mode()&os.ModeSymlink != 0, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("Hestia ingress rule state directory owner is invalid")
	}
	return nil
}

// validIngressRuleStateFile accepts only one private regular registry file owned by the effective user.
func validIngressRuleStateFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && info.Mode().Perm() == 0600 &&
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky|os.ModeSymlink) == 0 &&
		ok && stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 && info.Size() <= maxIngressRuleStateSize
}

// reconcileOwnedIngressRules marks only registry-backed kernel rules as Hestia-owned and prunes identities no longer present.
func reconcileOwnedIngressRules(path string, rules []ingressRule) ([]ingressRule, error) {
	registered, err := readOwnedIngressRules(path)
	if err != nil {
		return nil, err
	}
	registeredSet := make(map[ingressRule]struct{}, len(registered))
	for _, rule := range registered {
		registeredSet[rule] = struct{}{}
	}
	activeSet := make(map[ingressRule]struct{}, len(rules))
	for index := range rules {
		identity := rules[index]
		identity.Owned = false
		activeSet[identity] = struct{}{}
		if _, exists := registeredSet[identity]; exists {
			rules[index].Owned = true
		}
	}
	pruned := make([]ingressRule, 0, len(registered))
	for _, rule := range registered {
		if _, exists := activeSet[rule]; exists {
			pruned = append(pruned, rule)
		}
	}
	if len(pruned) != len(registered) {
		if err := writeOwnedIngressRules(path, pruned); err != nil {
			return nil, errors.New("cannot prune stale Hestia ingress rule ownership records")
		}
	}
	return rules, nil
}

// addOwnedIngressRule records a rule after the kernel confirms its creation; failures trigger immediate route-netlink rollback.
func addOwnedIngressRule(path string, rule ingressRule, rollback func() error) error {
	registered, err := readOwnedIngressRules(path)
	if err != nil {
		_ = rollback()
		return err
	}
	identity := rule
	identity.Owned = false
	for _, existing := range registered {
		if existing == identity {
			_ = rollback()
			return errors.New("Hestia ingress rule ownership identity already exists")
		}
	}
	registered = append(registered, identity)
	if err := writeOwnedIngressRules(path, registered); err != nil {
		_ = rollback()
		return errors.New("cannot persist Hestia ingress rule ownership")
	}
	return nil
}

// removeOwnedIngressRule drops one exact registry identity after the kernel confirms rule deletion.
func removeOwnedIngressRule(path string, rule ingressRule) error {
	registered, err := readOwnedIngressRules(path)
	if err != nil {
		return err
	}
	identity := rule
	identity.Owned = false
	filtered := make([]ingressRule, 0, len(registered))
	found := false
	for _, existing := range registered {
		if existing == identity {
			found = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !found {
		return errors.New("Hestia ingress rule ownership record is missing")
	}
	return writeOwnedIngressRules(path, filtered)
}
