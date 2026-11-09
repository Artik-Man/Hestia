// Package profileexec defines typed operations against the installed profile compiler and backend validator.
package profileexec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Operation selects one supported profile transformation.
type Operation uint8

const (
	Validate Operation = iota + 1
	Rebind
	Reorder
	CountryMap
	SaveList
	DeleteList
	MoveExit
	CreateGroup
	RenameGroup
	DeleteGroup
	Compile
	KeeneticIngress
)

// Request carries semantic transformation inputs; Source and Stage are trusted transaction directories.
type Request struct {
	Operation                                      Operation
	Source, Stage, ID, Target, Name, ExpectedGroup string
	UplinkDevice                                   string
	Priority                                       int
	PreserveWireguard                              bool
	Enabled                                        bool
}

// CompilerAPI is the platform boundary used by the transaction coordinator.
type CompilerAPI interface {
	Apply(context.Context, Request) error
	CheckBackend(context.Context, string) error
}

// Installed invokes fixed Linux programs; Run is an isolated command-observation seam.
type Installed struct {
	Run func(context.Context, string, ...string) error
}

// RunCommand runs a bounded command with the historical environment and secret-free error contract.
// It is adapter infrastructure, not an application operation API.
func RunCommand(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=" + CommandPath, "LANG=C"}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", filepath.Base(name), err)
	}
	return nil
}

// run selects the fixed production execution policy unless an isolated runner was injected.
func (i Installed) run(ctx context.Context, name string, args ...string) error {
	if i.Run != nil {
		return i.Run(ctx, name, args...)
	}
	return RunCommand(ctx, name, args...)
}

// Apply translates one known operation to the unchanged compiler argument sequence.
func (i Installed) Apply(ctx context.Context, r Request) error {
	args := []string{"-I", Compiler}
	switch r.Operation {
	case Validate:
		args = append(args, "--validate-managed", r.Source)
	case Rebind:
		args = append(args, "--rebind", r.Source, r.Stage, r.ID, r.Target)
	case Reorder:
		args = append(args, "--reorder", r.Source, r.Stage)
		if r.UplinkDevice != "" {
			args = append(args, r.UplinkDevice, "--keenetic")
		}
	case CountryMap:
		args = append(args, "--country-map", r.Source, r.Stage)
	case SaveList:
		args = append(args, "--save-list", r.Source, r.Stage, r.ID)
	case DeleteList:
		args = append(args, "--delete-list", r.Source, r.Stage, r.ID)
	case MoveExit:
		args = append(args, "--move-exit", r.Source, r.Stage, r.ID, r.ExpectedGroup, r.Target, strconv.Itoa(r.Priority))
	case CreateGroup:
		args = append(args, "--create-group", r.Source, r.Stage, r.ID, r.Name)
	case RenameGroup:
		args = append(args, "--rename-group", r.Source, r.Stage, r.ID, r.Name)
	case DeleteGroup:
		args = append(args, "--delete-group", r.Source, r.Stage, r.ID)
	case Compile:
		args = append(args, filepath.Join(r.Stage, "profile.json"), r.Stage, r.Stage)
		if r.PreserveWireguard {
			args = append(args, r.Source)
		}
		args = appendPlatformCompileFlag(args)
	case KeeneticIngress:
		action := "disable"
		if r.Enabled {
			action = "enable"
		}
		args = append(args, "--keenetic-ingress", r.Source, r.Stage, action)
		args = appendPlatformCompileFlag(args)
	default:
		return errors.New("unknown profile operation")
	}
	return i.run(ctx, Python, args...)
}

// CheckBackend asks the installed sing-box to validate the staged configuration without starting it.
func (i Installed) CheckBackend(ctx context.Context, path string) error {
	name, args := backendCheckCommand(path)
	return i.run(ctx, name, args...)
}
