// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package main

import (
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func icaclsT(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
}

// configDir is a temporary directory with an ACL of its own (the current
// user and SYSTEM, inherited by what is created in it), so the
// configfile integrity checks pass whatever the temporary directory
// inherits on this machine.
func configDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	icaclsT(t, dir, "/inheritance:r", "/grant:r", "*"+me.User.Sid.String()+":(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)")
	return dir
}

// letOthersWrite gives Everyone modify access to path.
func letOthersWrite(t *testing.T, path string) {
	t.Helper()
	icaclsT(t, path, "/grant", "*S-1-1-0:(M)")
}
