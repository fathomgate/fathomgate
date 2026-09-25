// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package fileacl

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// chmodACL runs /bin/chmod with an ACL argument (+a, -N) on path.
func chmodACL(t *testing.T, args ...string) {
	t.Helper()
	out, err := exec.Command("/bin/chmod", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("chmod %v: %v: %s", args, err, out)
	}
}

func extendedAt(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	got, err := Extended(f)
	if err != nil {
		t.Fatalf("Extended: %v", err)
	}
	return got
}

// TestExtendedDarwin reads real ACLs set with chmod(1): none on a new
// file, one after `chmod +a`, including a deny-only one, none after
// `chmod -N`, and one inherited from the folder.
func TestExtendedDarwin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if extendedAt(t, path) {
		t.Fatal("a new 0600 file reads as having an extended ACL")
	}
	chmodACL(t, "+a", "everyone allow read", path)
	if !extendedAt(t, path) {
		t.Fatal("an `everyone allow read` entry was not seen")
	}
	chmodACL(t, "-N", path)
	if extendedAt(t, path) {
		t.Fatal("the ACL removed with chmod -N is still seen")
	}
	chmodACL(t, "+a", "everyone deny write", path)
	if !extendedAt(t, path) {
		t.Fatal("a deny entry was not seen")
	}

	inherit := filepath.Join(dir, "inherit")
	if err := os.Mkdir(inherit, 0o700); err != nil {
		t.Fatal(err)
	}
	chmodACL(t, "+a", "everyone allow read,file_inherit", inherit)
	child := filepath.Join(inherit, "key")
	if err := os.WriteFile(child, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !extendedAt(t, child) {
		t.Fatal("an ACL entry inherited from the folder was not seen")
	}
}
