// Package socket defines fail-closed socket confinement for platform network adapters.
package socket

import (
	"errors"
	"syscall"
)

// Control is invoked before a socket sends its first packet.
type Control = func(string, string, syscall.RawConn) error

// Mode preserves the required ordering and error handling of socket options.
type Mode uint8

const (
	DeviceOnly Mode = iota
	DeviceThenMark
	MarkAndDevice
)

// Path identifies the kernel interface and optional policy mark for one socket.
type Path struct {
	Device string
	Mark   int
	Mode   Mode
}

// Binder supplies a platform callback; an unsupported platform must fail before sending.
type Binder interface{ Bind(Path) Control }

// applyOptions preserves option ordering, short-circuiting and combined failure semantics.
func applyOptions(p Path, device, mark func() error) error {
	if err := validatePath(p); err != nil {
		return err
	}
	switch p.Mode {
	case DeviceOnly:
		return device()
	case DeviceThenMark:
		if err := device(); err != nil {
			return err
		}
		if p.Mark != 0 {
			return mark()
		}
		return nil
	case MarkAndDevice:
		return errors.Join(mark(), device())
	default:
		return errors.New("unsupported socket binding mode")
	}
}

// validatePath rejects invalid interface names, out-of-range marks and inconsistent binding modes.
func validatePath(p Path) error {
	if len(p.Device) == 0 || len(p.Device) > 15 || p.Mark < 0 || uint64(p.Mark) > uint64(^uint32(0)) {
		return errors.New("invalid socket binding path")
	}
	for i := 0; i < len(p.Device); i++ {
		value := p.Device[i]
		if i == 0 && !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') || value == '_') {
			return errors.New("invalid socket binding path")
		}
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') || value == '_' || value == '.' || value == '-') {
			return errors.New("invalid socket binding path")
		}
	}
	switch p.Mode {
	case DeviceOnly:
		if p.Mark != 0 {
			return errors.New("invalid socket binding path")
		}
	case DeviceThenMark:
	case MarkAndDevice:
		if p.Mark == 0 {
			return errors.New("invalid socket binding path")
		}
	default:
		return errors.New("unsupported socket binding mode")
	}
	return nil
}
