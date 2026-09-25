// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// ADR 0028 on Unix: LoadKey accepts mode 0600 or 0400 and refuses any
// group or other permission bit, with the mode left as it was.
func TestLoadKeyUnixMode(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want string // "" accepts
	}{
		{"0600", 0o600, ""},
		{"0400", 0o400, ""},
		{"group readable", 0o640, "mode 0640"},
		{"group read only", 0o440, "mode 0440"},
		{"world readable", 0o604, "mode 0604"},
		{"group writable", 0o620, "mode 0620"},
		{"0644", 0o644, "chmod 600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := saveTestKey(t, dir, tc.name+".key")
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if _, err := LoadKey(p); err != nil {
					t.Fatalf("LoadKey: %v", err)
				}
			} else {
				assertKeyRefused(t, p, tc.want)
			}
			if m := mode(t, p); m != tc.mode {
				t.Fatalf("LoadKey changed the mode to %v", m)
			}
		})
	}
}

// A symbolic link at the key path is refused, even when it names a good
// key: whoever can plant the link chooses the key fathomgate signs with.
func TestLoadKeyUnixRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := saveTestKey(t, dir, "real.key")
	link := filepath.Join(dir, "audit.key")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	assertKeyRefused(t, link, "is a symbolic link")
	if _, err := LoadKey(target); err != nil {
		t.Fatalf("the target itself: %v", err)
	}
}

// A directory at the key path is refused as not a regular file.
func TestLoadKeyUnixRefusesDirectory(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.key")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	assertKeyRefused(t, p, "not a regular file")
}

// A key owned by another uid is refused. Creating one needs root.
func TestLoadKeyUnixRefusesOtherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a file to another uid; run the unix tests as root to exercise this")
	}
	p := saveTestKey(t, t.TempDir(), "audit.key")
	if err := os.Chown(p, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	assertKeyRefused(t, p, "owned by uid 4242")
}
