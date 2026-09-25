// SPDX-License-Identifier: FSL-1.1-ALv2

package configfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadOwnFile(t *testing.T) {
	dir := ownerOnlyDir(t, t.TempDir())
	p := write(t, dir, "p.yaml", "version: 1\n")
	b, err := Read(p, "the policy file", 1<<10)
	if err != nil || string(b) != "version: 1\n" {
		t.Fatalf("Read = %q, %v", b, err)
	}
	if err := CheckDir(dir, "the profiles directory"); err != nil {
		t.Fatalf("CheckDir: %v", err)
	}
	if _, err := Read(p, "the policy file", 4); err == nil || !strings.Contains(err.Error(), "larger than 4 bytes") {
		t.Fatalf("limit: %v", err)
	}
	if _, err := Read(p, "the policy file", 0); err == nil {
		t.Fatal("zero limit accepted")
	}
	if _, err := Read(dir, "the policy file", 1<<10); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("directory as file: %v", err)
	}
	if err := CheckDir(p, "the profiles directory"); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file as directory: %v", err)
	}
	if _, err := Read(filepath.Join(dir, "missing.yaml"), "the policy file", 1<<10); err == nil || errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing: %v", err)
	}
}
