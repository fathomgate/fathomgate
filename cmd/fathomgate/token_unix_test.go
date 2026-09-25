// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// writeOwnerOnly writes a token file readTokenFile accepts: mode 0600,
// whatever the umask.
func writeOwnerOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeShared gives a token file permissions another user could use.
func makeShared(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadTokenFileUnix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tok := []byte(testListenToken + "\n")
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want string // "" accepts
	}{
		{"0600", 0o600, ""},
		{"0400", 0o400, ""},
		{"group readable", 0o640, "mode 0640"},
		{"world readable", 0o604, "mode 0604"},
		{"group writable", 0o620, "mode 0620"},
		{"everyone", 0o666, "chmod 600"},
	} {
		path := filepath.Join(dir, tc.name)
		writeOwnerOnly(t, path, tok)
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		got, err := readTokenFile(path)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want == "" && string(got) != string(tok):
			t.Errorf("%s: read %q", tc.name, got)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), dir) {
			t.Errorf("%s: the error quotes the path: %v", tc.name, err)
		}
	}

	target := filepath.Join(dir, "target")
	writeOwnerOnly(t, target, tok)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		link: "symbolic link",
		hard: "2 hard links",
		dir:  "not a regular file",
		// Opened without blocking for a writer, then refused.
		fifo:                               "not a regular file",
		filepath.Join(dir, "no-such-file"): "cannot open the token file",
	} {
		_, err := readTokenFile(path)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", filepath.Base(path), err, want)
		}
		if err != nil && strings.Contains(err.Error(), dir) {
			t.Errorf("%s: the error quotes the path: %v", filepath.Base(path), err)
		}
	}
}
