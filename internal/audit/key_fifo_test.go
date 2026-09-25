// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix && !aix && !illumos && !solaris

package audit

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/fathomgate/fathomgate/internal/secretfile"
)

// A named pipe at the key or public key path is refused without blocking
// for a writer (security review of PR #155, L2 for the public key).
func TestKeyLoadersRefuseFIFO(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fifo := filepath.Join(dir, "audit.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]error, 1)
	go func() {
		_, errKey := LoadKey(fifo)
		_, errPub := LoadPublicKey(fifo)
		done <- [2]error{errKey, errPub}
	}()
	select {
	case errs := <-done:
		if !errors.Is(errs[0], secretfile.ErrUnsafe) || !strings.Contains(errs[0].Error(), "not a regular file") {
			t.Errorf("LoadKey: err = %v, want a refusal naming not a regular file", errs[0])
		}
		if errs[1] == nil || !strings.Contains(errs[1].Error(), "not a regular file") {
			t.Errorf("LoadPublicKey: err = %v, want not a regular file", errs[1])
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a key loader blocked on a named pipe")
	}
}
