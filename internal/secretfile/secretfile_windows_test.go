// SPDX-License-Identifier: Apache-2.0

//go:build windows

package secretfile

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// setDACL gives path the current user as owner and the protected DACL in
// sddl.
func setDACL(t *testing.T, path, sddl string) {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + sddl)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func currentSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// writeOwnerOnly writes a file Read accepts: owned by the current user,
// with a protected DACL granting only that user.
func writeOwnerOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, "D:P(A;;FA;;;"+currentSID(t)+")")
}

// makeShared grants BUILTIN\Users read access.
func makeShared(t *testing.T, path string) {
	t.Helper()
	setDACL(t, path, "D:P(A;;FA;;;"+currentSID(t)+")(A;;FR;;;BU)")
}
