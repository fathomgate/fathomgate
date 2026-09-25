// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package configfile

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// TestUnixModes: a group- or other-writable file or directory is refused;
// read bits for others are fine (the files are not secret).
func TestUnixModes(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	p := write(t, dir, "p.yaml", "version: 1\n")
	for _, tc := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o600, true}, {0o644, true}, {0o444, true}, {0o664, false}, {0o646, false}, {0o666, false}} {
		if err := os.Chmod(p, tc.mode); err != nil {
			t.Fatal(err)
		}
		_, err := Read(p, "the policy file", 1<<10)
		if tc.ok != (err == nil) {
			t.Errorf("mode %04o: %v", tc.mode, err)
		}
		if !tc.ok && (!errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "chmod go-w")) {
			t.Errorf("mode %04o: %v", tc.mode, err)
		}
	}
	sub := ownerOnlyDir(t, t.TempDir())
	if err := os.Chmod(sub, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(sub, "the profiles directory"); !errors.Is(err, ErrUnsafe) {
		t.Errorf("group-writable directory: %v", err)
	}
	if err := os.Chmod(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(sub, "the profiles directory"); err != nil {
		t.Errorf("0755 directory: %v", err)
	}
}

// TestUnixOwner: a file owned by another user (not root) is refused. The
// test calls check with an euid the file is not owned by.
func TestUnixOwner(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file passes the owner rule")
	}
	p := write(t, ownerOnlyDir(t, t.TempDir()), "p.yaml", "version: 1\n")
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := check(f, "the policy file", false, os.Geteuid()+1); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "is owned by uid") {
		t.Fatalf("other owner: %v", err)
	}
}
