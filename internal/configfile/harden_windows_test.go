// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"testing"

	"golang.org/x/sys/windows"
)

// ownerOnlyDir gives dir an ACL of its own (the current user and SYSTEM,
// inherited by what is created in it), so the test does not depend on
// what the temporary directory inherits on this machine.
func ownerOnlyDir(t *testing.T, dir string) string {
	t.Helper()
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	icacls(t, dir, "/inheritance:r", "/grant:r", "*"+me.User.Sid.String()+":(OI)(CI)(F)", "*S-1-5-18:(OI)(CI)(F)")
	return dir
}
