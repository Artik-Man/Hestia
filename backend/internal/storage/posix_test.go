package storage

import (
	"os"
	"path/filepath"
	"testing"
)

// TestProtectedOpen preserves rejection of links and ordinary files requested as directories.
func TestProtectedOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	if err := os.WriteFile(path, []byte("state"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if file, err := OpenFile(link, ReadOnly|NoFollow, 0); !IsSymlink(err) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("symlink accepted: %v", err)
	}
	if file, err := OpenFile(path, ReadOnly|Directory, 0); err == nil {
		file.Close()
		t.Fatal("regular file accepted as directory")
	}
	file, err := OpenFile(path, ReadOnly|NoFollow|Nonblock, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := Stat(info)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 || stat.Ino == 0 {
		t.Fatalf("invalid metadata: %+v", stat)
	}
	if _, ok := Stat(nil); ok {
		t.Fatal("nil metadata accepted")
	}
}

// TestLockContention verifies nonblocking exclusivity and release across independent descriptors.
func TestLockContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := OpenFile(path, Create|ReadWrite|NoFollow, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenFile(path, ReadOnly|NoFollow, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := Flock(first, LockExclusive|LockNonblock); err != nil {
		t.Fatal(err)
	}
	if err := Flock(second, LockShared|LockNonblock); !IsWouldBlock(err) {
		t.Fatalf("expected conflict: %v", err)
	}
	if err := Flock(first, LockUnlock); err != nil {
		t.Fatal(err)
	}
	if err := Flock(second, LockShared|LockNonblock); err != nil {
		t.Fatal(err)
	}
}

// TestInvalidOptions rejects flags with no defined filesystem contract.
func TestInvalidOptions(t *testing.T) {
	if _, err := OpenFile("unused", OpenFlags(1<<30), 0); err != os.ErrInvalid {
		t.Fatalf("invalid flags: %v", err)
	}
	if err := Flock(nil, LockShared|LockExclusive); err != os.ErrInvalid {
		t.Fatalf("invalid mode: %v", err)
	}
}
