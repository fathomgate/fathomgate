// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package secretfile

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
)

// writeOwnerOnly writes a file Read accepts: mode 0600, whatever the umask.
func writeOwnerOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeShared makes a file readable by its group.
func makeShared(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
}

// An ACL read failure keeps its cause without the path: neither the
// message nor errors.As reaches the *fs.PathError.
func TestACLReadRefusalIsPathless(t *testing.T) {
	t.Parallel()
	const path = "/FAKE/secret/path"
	err := aclReadRefusal("the test secret", &fs.PathError{Op: "fgetattrlist", Path: path, Err: syscall.EIO})
	if !errors.Is(err, ErrUnsafe) || !errors.Is(err, syscall.EIO) {
		t.Fatalf("err = %v, want ErrUnsafe and EIO", err)
	}
	if _, ok := errors.AsType[*fs.PathError](err); ok {
		t.Fatal("errors.As reaches the *fs.PathError")
	}
	if strings.Contains(err.Error(), path) {
		t.Fatalf("the message quotes the path: %v", err)
	}
}
