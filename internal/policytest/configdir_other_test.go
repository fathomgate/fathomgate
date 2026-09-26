// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package policytest

import (
	"os"
	"testing"
)

// configDir is a temporary directory (mode 0700) for configuration files
// that pass the configfile integrity checks.
func configDir(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// letOthersWrite makes path writable by group and others.
func letOthersWrite(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, fi.Mode().Perm()|0o022); err != nil {
		t.Fatal(err)
	}
}
