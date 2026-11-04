package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// exceptions owns a dedicated, initially empty live source rule-set for the second group exit.
type exceptions struct {
	dir                       *os.File
	path                      string
	last                      []byte
	info                      os.FileInfo
	group, primary, alternate string
	targets                   map[Target]bool
	addresses                 []string
}

// RunSteerCLI samples configured targets directly and publishes only UDP exceptions for the second exit.
func RunSteerCLI(ctx context.Context, args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("hestia steer", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "", "observer JSON configuration")
	path := flags.String("rules", "", "dedicated initially empty sing-box rule-set")
	rounds := flags.Int("rounds", 0, "number of rounds; zero continues until canceled")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *config == "" || *path == "" || *rounds < 0 || flags.NArg() != 0 {
		return fmt.Errorf("usage: hestia steer -config FILE -rules PATH [-rounds N]")
	}
	s, err := readSettings(*config)
	if err != nil {
		return err
	}
	rules, err := openExceptions(*path, s)
	if err != nil {
		return err
	}
	defer rules.close()
	log := json.NewEncoder(output)
	return runReports(ctx, s, *rounds, func(r Report) error {
		action, applyErr := rules.apply(r)
		event := struct {
			Report
			Action string `json:"rule_action"`
			Error  string `json:"rule_error,omitempty"`
		}{Report: r, Action: action}
		if applyErr != nil {
			event.Error = applyErr.Error()
		}
		if err := log.Encode(event); err != nil {
			return err
		}
		return applyErr
	})
}

// openExceptions locks a trusted working directory and accepts only an operator-provisioned empty v3 rule file.
func openExceptions(path string, s Settings) (*exceptions, error) {
	if len(s.Connections) != 2 {
		return nil, fmt.Errorf("steering requires exactly two connections")
	}
	targets := make(map[Target]bool)
	for _, t := range s.Targets {
		if t.Protocol == "udp" {
			targets[t] = true
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("steering requires a UDP target")
	}
	root := filepath.Dir(path)
	dir, err := os.OpenFile(root, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	owned, err := dir.Stat()
	if err != nil || !trusted(owned) {
		dir.Close()
		return nil, fmt.Errorf("rule directory must be owned by this user and not writable by others: %s", root)
	}
	if err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		dir.Close()
		return nil, fmt.Errorf("lock rule directory: %w", err)
	}
	e := &exceptions{dir: dir, path: path, group: s.Group, primary: s.Connections[0].ID, alternate: s.Connections[1].ID, targets: targets}
	e.last, e.info, err = readRule(path)
	if err != nil {
		e.close()
		return nil, err
	}
	var compact bytes.Buffer
	if err = json.Compact(&compact, e.last); err != nil || (compact.String() != `{"version":3,"rules":[]}` && compact.String() != `{"rules":[],"version":3}`) {
		e.close()
		return nil, fmt.Errorf("refusing nonempty or foreign initial rule-set: %s", path)
	}
	return e, nil
}

// trusted reports whether the current user owns a path and only the owner can write it.
func trusted(info os.FileInfo) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	return ok && owner.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0022 == 0
}

// readRule reads bounded source data without following symlinks or blocking on special files.
func readRule(path string) ([]byte, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !trusted(info) {
		return nil, nil, fmt.Errorf("expected owned regular rule file: %s", path)
	}
	const maxSize = 64 << 10
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if len(data) > maxSize {
		return nil, nil, fmt.Errorf("rule-set exceeds %d bytes", maxSize)
	}
	return data, info, err
}

// close releases the directory lock; the last successfully published rules stay live.
func (e *exceptions) close() { e.dir.Close() }

// apply changes only the addressed UDP scope on an explicit measured advantage.
func (e *exceptions) apply(r Report) (string, error) {
	if r.Protocol != "udp" {
		return "not_applicable", nil
	}
	if r.Group != e.group || !e.targets[r.Target] || (r.Recommended != e.primary && r.Recommended != e.alternate) {
		return "error", fmt.Errorf("unconfigured steering scope or connection")
	}
	if r.Reason != "better_delivery" {
		return "unchanged", nil
	}
	next := slices.Clone(e.addresses)
	index, exists := slices.BinarySearch(next, r.Address)
	add := r.Recommended == e.alternate
	if add == exists {
		return "unchanged", nil
	}
	action := "removed"
	if add {
		action = "added"
		next = slices.Insert(next, index, r.Address)
	} else {
		next = slices.Delete(next, index, index+1)
	}
	if err := e.publish(next); err != nil {
		return "error", err
	}
	e.addresses = next
	return action, nil
}

// publish atomically replaces the previously verified inode with one complete source rule-set.
func (e *exceptions) publish(next []string) error {
	type cidrRule struct {
		CIDR []string `json:"ip_cidr"`
	}
	set := struct {
		Version int        `json:"version"`
		Rules   []cidrRule `json:"rules"`
	}{3, make([]cidrRule, 0, len(next))}
	for _, addr := range next {
		set.Rules = append(set.Rules, cidrRule{[]string{addr + "/32"}})
	}
	data, err := json.Marshal(set)
	if err != nil {
		return err
	}
	raw, info, err := readRule(e.path)
	if err != nil {
		return err
	}
	if !os.SameFile(e.info, info) || !bytes.Equal(e.last, raw) {
		return fmt.Errorf("live rule-set was edited externally")
	}
	temp, err := os.CreateTemp(filepath.Dir(e.path), ".hestia-steer-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chown(-1, int(info.Sys().(*syscall.Stat_t).Gid)); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Chmod(info.Mode().Perm())
	}
	if err == nil {
		err = temp.Sync()
	}
	after, statErr := temp.Stat()
	closeErr := temp.Close()
	if err != nil {
		return err
	}
	if statErr != nil {
		return statErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp.Name(), e.path); err != nil {
		return err
	}
	e.info, e.last = after, data
	return nil
}
