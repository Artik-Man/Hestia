//go:build linux && keenetic

// Package keeneticroute provides the fixed Entware route-command adapter for Keenetic builds.
package keeneticroute

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/network"
)

const (
	commandTimeout   = 3 * time.Second
	maxCommandOutput = 1 << 20
)

var (
	markToken   = regexp.MustCompile(`^0x[0-9a-f]{1,8}$`)
	deviceToken = regexp.MustCompile(`^awg[0-9]{1,2}$`)
)

// ExecRouteRunner invokes the installed Entware ip applet without a shell.
type ExecRouteRunner struct{}

// Run executes one bounded route command, uses BusyBox's documented list verbs for show aliases, and returns only output or a sanitized error.
func (ExecRouteRunner) Run(parent context.Context, args ...string) ([]byte, error) {
	if !validRouteCommand(args) {
		return nil, errors.New("unsupported Keenetic route command")
	}
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()

	commandArgs := keeneticCommandArgs(args)
	if len(args) >= 3 && args[2] == "show" {
		switch args[1] {
		case "route", "rule":
			commandArgs[2] = "list"
		}
	}
	command := exec.CommandContext(ctx, "/opt/sbin/ip", commandArgs...)
	command.Env = []string{"PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var stdout, stderr boundedOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("Entware ip command timed out")
		}
		return nil, errors.New("Entware ip command failed")
	}
	return bytes.Clone(stdout.Bytes()), nil
}

// keeneticCommandArgs translates Linux terminal rule actions into the equivalent Keenetic ip syntax.
func keeneticCommandArgs(args []string) []string {
	commandArgs := append([]string(nil), args...)
	if len(commandArgs) == 8 && (commandArgs[0] == "-4" || commandArgs[0] == "-6") {
		if commandArgs[1] == "rule" && (commandArgs[2] == "add" || commandArgs[2] == "del") && commandArgs[7] == "unreachable" {
			return append(commandArgs[:7], "lookup", "unspec", "type", "blackhole")
		}
	}
	return commandArgs
}

// validRouteCommand accepts read-only route inventory and the exact route mutations reserved by Hestia.
func validRouteCommand(args []string) bool {
	if len(args) == 3 && args[0] == "-o" && args[1] == "link" && args[2] == "show" {
		return true
	}
	if len(args) < 3 || (args[0] != "-4" && args[0] != "-6") {
		return false
	}
	family := args[0]
	if len(args) == 3 && args[1] == "rule" && args[2] == "show" {
		return true
	}
	if len(args) == 5 && args[1] == "route" && args[2] == "show" && args[3] == "table" {
		return validTable(args[4])
	}
	switch args[1] {
	case "route":
		return validRouteMutation(args, family)
	case "rule":
		return validRuleMutation(args)
	default:
		return false
	}
}

// validRouteMutation accepts only unreachable guards and AWG default routes in reserved tables.
func validRouteMutation(args []string, family string) bool {
	if len(args) == 9 && (args[2] == "add" || args[2] == "del") {
		return args[3] == "unreachable" && args[4] == "default" && args[5] == "table" &&
			validTable(args[6]) && args[7] == "metric" && args[8] == "32767"
	}
	if len(args) == 10 && (args[2] == "add" || args[2] == "del") {
		if family != "-4" || args[3] != "default" || args[4] != "dev" || args[6] != "table" || args[8] != "metric" || args[9] != "100" {
			return false
		}
		slot, ok := awgSlotFromTable(args[7])
		return ok && args[5] == "awg"+strconv.Itoa(slot) && deviceToken.MatchString(args[5])
	}
	return false
}

// validRuleMutation accepts only slot-bound AWG mark lookups and outer unreachable rules.
func validRuleMutation(args []string) bool {
	if len(args) == 9 && (args[2] == "add" || args[2] == "del") {
		if args[3] != "priority" || args[5] != "fwmark" || args[7] != "lookup" {
			return false
		}
		slot, ok := awgSlotFromTable(args[8])
		if !ok || args[6] != formatMark(0x202+slot)+"/0xffffffff" {
			return false
		}
		priority, err := strconv.Atoi(args[4])
		if err != nil || strconv.Itoa(priority) != args[4] {
			return false
		}
		return priority == network.MarkRulePriority(slot) || (args[2] == "del" && priority == 1002+slot)
	}
	if len(args) == 8 && (args[2] == "add" || args[2] == "del") {
		if args[3] != "priority" || args[5] != "fwmark" || args[7] != "unreachable" {
			return false
		}
		priority, err := strconv.Atoi(args[4])
		if err != nil || strconv.Itoa(priority) != args[4] || !validMarkMask(args[6]) {
			return false
		}
		for slot := 0; slot < network.SlotCount; slot++ {
			currentPriority := priority == network.OuterRulePriority(slot)
			legacyDelete := args[2] == "del" && priority == 1100+slot
			if (currentPriority || legacyDelete) && args[6] == formatMark(0x51000+slot)+"/0xffffffff" {
				return true
			}
		}
		return false
	}
	return false
}

// awgSlotFromTable parses only the 50 numeric routing tables reserved for AWG instances.
func awgSlotFromTable(value string) (int, bool) {
	table, err := strconv.Atoi(value)
	if err != nil || table < 202 || table >= 202+50 || strconv.Itoa(table) != value {
		return 0, false
	}
	return table - 202, true
}

// formatMark produces the canonical lowercase hexadecimal form used by the reserved policies.
func formatMark(value int) string { return "0x" + strconv.FormatInt(int64(value), 16) }

// validTable accepts only canonical numeric tables reserved for AWG instances.
func validTable(value string) bool {
	_, ok := awgSlotFromTable(value)
	return ok
}

// validMarkMask accepts one canonical hexadecimal mark with the full-width mask only.
func validMarkMask(value string) bool {
	mark, mask, ok := strings.Cut(value, "/")
	if !ok || mask != "0xffffffff" || !markToken.MatchString(mark) {
		return false
	}
	_, err := strconv.ParseUint(strings.TrimPrefix(mark, "0x"), 16, 32)
	return err == nil
}

// boundedOutput stores at most maxCommandOutput bytes from a child process stream.
type boundedOutput struct {
	bytes.Buffer
}

// Write rejects output that would exceed the fixed memory limit.
func (b *boundedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > maxCommandOutput {
		return 0, errors.New("route command output exceeded its limit")
	}
	return b.Buffer.Write(data)
}
