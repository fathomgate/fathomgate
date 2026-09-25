// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, tc.name)
			writeOwnerOnly(t, path, tok)
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatal(err)
			}
			got, err := readTokenFile(path)
			switch {
			case tc.want == "" && err != nil:
				t.Error(err)
			case tc.want == "" && string(got) != string(tok):
				t.Errorf("read %q", got)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), dir) {
				t.Errorf("the error quotes the path: %v", err)
			}
		})
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
	cases := []struct{ name, path, want string }{
		{"symbolic link", link, "symbolic link"},
		{"hard link", hard, "2 hard links"},
		{"directory", dir, "not a regular file"},
		{"missing", filepath.Join(dir, "no-such-file"), "cannot open the token file"},
	}
	fifo := filepath.Join(dir, "fifo")
	switch err := mkfifo(fifo); {
	case err == nil:
		// Opened without blocking for a writer, then refused.
		cases = append(cases, struct{ name, path, want string }{"named pipe", fifo, "not a regular file"})
	case errors.Is(err, errors.ErrUnsupported):
		t.Log("named pipe case left out: no mkfifo on this platform")
	default:
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := readTokenFile(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), dir) {
				t.Errorf("the error quotes the path: %v", err)
			}
		})
	}
}
