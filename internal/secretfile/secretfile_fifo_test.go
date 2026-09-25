// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix && !aix && !illumos && !solaris

package secretfile

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A named pipe is opened without blocking for a writer (O_NONBLOCK) and
// refused as not a regular file.
func TestReadFIFO(t *testing.T) {
	t.Parallel()
	fifo := filepath.Join(t.TempDir(), "secret")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Read(fifo, "the test secret", 4096)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want a refusal naming not a regular file", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read blocked on a named pipe")
	}
}
