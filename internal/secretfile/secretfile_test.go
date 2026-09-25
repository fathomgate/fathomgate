// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package secretfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "FAKE-secret-0123456789abcdef0123456789abcdef\n"

func TestReadOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	writeOwnerOnly(t, p, []byte(secret))
	got, err := Read(p, "the test secret", 4096)
	if err != nil || string(got) != secret {
		t.Fatalf("Read = %q, %v", got, err)
	}

	// Exactly the limit is read; one byte more is refused.
	if _, err := Read(p, "the test secret", int64(len(secret))); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err = Read(p, "the test secret", int64(len(secret)-1))
	if err == nil || !strings.Contains(err.Error(), "the test secret is larger than") {
		t.Fatalf("over the limit: %v", err)
	}
}

// Every refusal matches ErrUnsafe and names the file as the caller did;
// an open failure does not match it. Neither quotes the path or content.
func TestReadErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	writeOwnerOnly(t, p, []byte(secret))
	makeShared(t, p)
	_, err := Read(p, "the test secret", 4096)
	if !errors.Is(err, ErrUnsafe) {
		t.Fatalf("shared file: err = %v, want ErrUnsafe", err)
	}
	if !strings.HasPrefix(err.Error(), "the test secret ") {
		t.Errorf("shared file: err = %v, want it to start with the name given", err)
	}
	if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "FAKE-secret") {
		t.Errorf("shared file: the error quotes the path or the content: %v", err)
	}

	_, err = Read(filepath.Join(dir, "absent"), "the test secret", 4096)
	if err == nil || errors.Is(err, ErrUnsafe) {
		t.Fatalf("missing file: err = %v, want an open error that is not ErrUnsafe", err)
	}
	if !strings.Contains(err.Error(), "cannot open the test secret") || strings.Contains(err.Error(), dir) {
		t.Errorf("missing file: err = %v", err)
	}
}

// A second hard link is refused through either name.
func TestReadHardLink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	writeOwnerOnly(t, p, []byte(secret))
	link := filepath.Join(dir, "link")
	if err := os.Link(p, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{p, link} {
		if _, err := Read(name, "the test secret", 4096); !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "2 hard links") {
			t.Errorf("%s: err = %v, want a refusal naming 2 hard links", filepath.Base(name), err)
		}
	}
}
