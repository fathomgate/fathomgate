// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretfile

import (
	"os"
	"testing"
)

// writeOwnerOnly writes a file Read accepts: mode 0600, whatever the umask.
func writeOwnerOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeShared makes a file readable by its group.
func makeShared(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
}
