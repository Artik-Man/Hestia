package storage

import (
	"errors"
	"os"
	"syscall"
)

// Metadata contains ownership and file identity used by secure storage contracts.
type Metadata struct {
	Uid, Gid   uint32
	Nlink, Ino uint64
}

// Stat extracts filesystem metadata, returning false for unsupported metadata representations.
func Stat(info os.FileInfo) (*Metadata, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, false
	}
	return &Metadata{Uid: stat.Uid, Gid: stat.Gid, Nlink: uint64(stat.Nlink), Ino: stat.Ino}, true
}

// MustStat returns metadata for an operating-system file or panics if the platform violates that contract.
// Consumers handling untrusted or synthetic FileInfo values should use Stat instead.
func MustStat(info os.FileInfo) *Metadata {
	stat, ok := Stat(info)
	if !ok {
		panic("unsupported filesystem metadata")
	}
	return stat
}

// OpenFlags specifies access and filesystem safety constraints independently of native flag values.
type OpenFlags uint32

const (
	ReadOnly  OpenFlags = 0
	WriteOnly OpenFlags = 1 << iota
	ReadWrite
	Create
	Exclusive
	NoFollow
	Nonblock
	Directory
	CloseOnExec
)

// OpenFile opens a file with explicit access and safety constraints; errors retain their native identity.
func OpenFile(path string, flags OpenFlags, mode os.FileMode) (*os.File, error) {
	if flags & ^(WriteOnly|ReadWrite|Create|Exclusive|NoFollow|Nonblock|Directory|CloseOnExec) != 0 || flags&(WriteOnly|ReadWrite) == WriteOnly|ReadWrite {
		return nil, os.ErrInvalid
	}
	native := os.O_RDONLY
	for _, pair := range []struct {
		option OpenFlags
		native int
	}{
		{WriteOnly, os.O_WRONLY}, {ReadWrite, os.O_RDWR}, {Create, os.O_CREATE}, {Exclusive, os.O_EXCL},
		{NoFollow, syscall.O_NOFOLLOW}, {Nonblock, syscall.O_NONBLOCK}, {Directory, syscall.O_DIRECTORY}, {CloseOnExec, syscall.O_CLOEXEC},
	} {
		if flags&pair.option != 0 {
			native |= pair.native
		}
	}
	return os.OpenFile(path, native, mode)
}

// LockMode describes shared/exclusive ownership and whether acquisition may wait.
type LockMode uint8

const (
	LockShared LockMode = 1 << iota
	LockExclusive
	LockNonblock
	LockUnlock
)

// Flock acquires or releases a filesystem advisory lock, preserving native contention errors.
func Flock(file *os.File, mode LockMode) error {
	if mode != LockShared && mode != LockExclusive && mode != LockShared|LockNonblock && mode != LockExclusive|LockNonblock && mode != LockUnlock {
		return os.ErrInvalid
	}
	native := 0
	for _, pair := range []struct {
		option LockMode
		native int
	}{
		{LockShared, syscall.LOCK_SH}, {LockExclusive, syscall.LOCK_EX}, {LockNonblock, syscall.LOCK_NB}, {LockUnlock, syscall.LOCK_UN},
	} {
		if mode&pair.option != 0 {
			native |= pair.native
		}
	}
	return syscall.Flock(int(file.Fd()), native)
}

// IsWouldBlock reports an advisory lock conflict without exposing native error constants.
func IsWouldBlock(err error) bool { return errors.Is(err, syscall.EWOULDBLOCK) }

// IsSymlink reports the native refusal to follow a symbolic link.
func IsSymlink(err error) bool { return errors.Is(err, syscall.ELOOP) }
