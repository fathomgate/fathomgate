// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadTokenFileDarwinACL (L2 in the security review of PR #109): a
// token file with mode 0600 and an extended ACL, set with `chmod +a` or
// inherited from its folder, is refused; the same file after `chmod -N`
// is read.
func TestReadTokenFileDarwinACL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	chmod := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("/bin/chmod", args...).CombinedOutput(); err != nil {
			t.Fatalf("chmod %v: %v: %s", args, err, out)
		}
	}
	const want = "the token file has an extended ACL"
	path := tokenFile(t, dir, "acl", testListenToken+"\n")
	chmod("+a", "everyone allow read", path)
	if _, err := readTokenFile(path); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("with an ACL entry: error %v, want %q", err, want)
	}
	chmod("-N", path)
	if got, err := readTokenFile(path); err != nil || string(got) != testListenToken+"\n" {
		t.Fatalf("after chmod -N: %q, %v", got, err)
	}

	inherit := filepath.Join(dir, "inherit")
	if err := os.Mkdir(inherit, 0o700); err != nil {
		t.Fatal(err)
	}
	chmod("+a", "everyone allow read,file_inherit", inherit)
	child := tokenFile(t, inherit, "child", testListenToken+"\n")
	_, err := readTokenFile(child)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("with an inherited ACL entry: error %v, want %q", err, want)
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("the error quotes the path: %v", err)
	}
}
