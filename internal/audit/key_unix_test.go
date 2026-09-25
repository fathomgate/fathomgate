// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// looseLog writes a valid two-event chain at path and makes it 0644.
func looseLog(t *testing.T, path string) {
	t.Helper()
	writeChain(t, path, 2, Options{})
	// Simulates a log left world-readable.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// An existing 0644 target is refused, not overwritten and not chmodded.
func TestSaveKeyRefusesExisting0644(t *testing.T) {
	_, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	kp := filepath.Join(t.TempDir(), "audit.key")
	if err := os.WriteFile(kp, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulates an operator's world-readable file.
	if err := os.Chmod(kp, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveKey(kp, priv); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want fs.ErrExist", err)
	}
	if m := mode(t, kp); m != 0o644 {
		t.Fatalf("refused target mode changed to %v", m)
	}
}

// A symlink at the key path is refused too (O_EXCL does not follow it).
func TestSaveKeyRefusesSymlink(t *testing.T) {
	_, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	kp := filepath.Join(dir, "audit.key")
	if err := os.Symlink(target, kp); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := SaveKey(kp, priv); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("err = %v, want fs.ErrExist", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("symlink target was created: %v", err)
	}
}

// A dangling symlink at the public key or log path is not followed either:
// nothing is created at the link's target.
func TestDanglingSymlinkNotFollowed(t *testing.T) {
	pub, _, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		create func(path string) error
		want   error
	}{
		{"pub", func(p string) error { return SavePublicKey(p, pub) }, fs.ErrExist},
		{"log", func(p string) error {
			w, err := NewWriter(p, Options{})
			if err == nil {
				_ = w.Close()
			}
			return err
		}, errUnsafeLog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "attacker-chosen")
			link := filepath.Join(dir, "audit."+tc.name)
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink: %v", err)
			}
			if err := tc.create(link); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("file created at the symlink target: %v", err)
			}
		})
	}
}

func TestSavePublicKeyMode(t *testing.T) {
	pub, _, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pp := filepath.Join(t.TempDir(), "audit.pub")
	if err := SavePublicKey(pp, pub); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, pp); m != 0o644 {
		t.Fatalf("public key mode %v, want 0644", m)
	}
}

// A new log is 0600; an existing 0644 log we own is corrected to 0600 on
// resume and keeps its chain.
func TestWriterLogMode(t *testing.T) {
	dir := t.TempDir()
	fresh := filepath.Join(dir, "new.jsonl")
	writeChain(t, fresh, 2, Options{})
	if m := mode(t, fresh); m != 0o600 {
		t.Fatalf("new log mode %v, want 0600", m)
	}

	// Simulates a log left world-readable.
	if err := os.Chmod(fresh, 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := NewWriter(fresh, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sampleEvent(3)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, fresh); m != 0o600 {
		t.Fatalf("resumed log mode %v, want 0600", m)
	}
	if rep, err := Verify(fresh); err != nil || !rep.OK || rep.Events != 3 {
		t.Fatalf("resumed chain %+v, %v", rep, err)
	}
}

// H1: a symlink at the log path is refused and its target is not chmodded
// (confused deputy: a root writer pointed at audit.jsonl -> /etc/passwd).
func TestNewWriterRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	looseLog(t, target)
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := NewWriter(link, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	if m := mode(t, target); m != 0o644 {
		t.Fatalf("symlink target mode changed to %v", m)
	}
}

// H1: a hard link is refused and the shared inode is not chmodded.
func TestNewWriterHardLinkKeepsMode(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "orig.jsonl")
	looseLog(t, orig)
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Link(orig, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(link, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	if m := mode(t, orig); m != 0o644 {
		t.Fatalf("hard-linked file mode changed to %v", m)
	}
}

// Q2: permissions change only after the chain verifies.
func TestNewWriterBrokenChainKeepsMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(p, []byte("not json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulates a log left world-readable.
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(p, Options{}); err == nil {
		t.Fatal("NewWriter should refuse a broken chain")
	}
	if m := mode(t, p); m != 0o644 {
		t.Fatalf("broken log mode changed to %v before verification", m)
	}
}

// H2: a log owned by another uid is refused. Creating one needs root.
func TestNewWriterRefusesOtherOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown a file to another uid; run the unix tests as root to exercise this")
	}
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	looseLog(t, p)
	if err := os.Chown(p, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWriter(p, Options{}); !errors.Is(err, errUnsafeLog) {
		t.Fatalf("err = %v, want errUnsafeLog", err)
	}
	if m := mode(t, p); m != 0o644 {
		t.Fatalf("foreign log mode changed to %v", m)
	}
}
