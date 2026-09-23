//go:build !windows

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
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
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

// A new log is 0600; an existing 0644 log is corrected to 0600 on resume and
// keeps its chain.
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
