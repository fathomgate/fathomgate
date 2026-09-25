// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// setKeySecurity gives path the current user as owner and the DACL in
// sddl, protected when sddl starts with "D:P".
func setKeySecurity(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("O:" + currentUser(t).String() + sddl)
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
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if strings.HasPrefix(sddl, "D:P") {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// keyPEM returns the bytes of a key file SaveKey wrote.
func keyPEM(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(saveTestKey(t, t.TempDir(), "src.key"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ADR 0028 on Windows: LoadKey accepts a key only with a protected DACL
// whose allow entries name the owner and SYSTEM, and refuses one that
// inherits from its folder or grants anyone else access.
func TestLoadKeyWindowsDACL(t *testing.T) {
	dir := looseDir(t)
	me := currentUser(t).String()
	key := keyPEM(t)
	for _, tc := range []struct {
		name string
		sddl string // "" leaves what the loose folder gives the file
		want string // "" accepts
	}{
		{"owner only", "D:P(A;;FA;;;" + me + ")", ""},
		{"owner and SYSTEM", "D:P(A;;FA;;;" + me + ")(A;;FA;;;SY)", ""},
		{"owner read only", "D:P(A;;FR;;;" + me + ")", ""},
		{"deny entries are fine", "D:P(D;;FA;;;BG)(A;;FA;;;" + me + ")", ""},
		{"inherited", "", "inherits permissions from its folder"},
		{"unprotected", "D:(A;;FA;;;" + me + ")", "inherits permissions from its folder"},
		{"users can read", "D:P(A;;FA;;;" + me + ")(A;;FR;;;BU)", "grants access to S-1-5-32-545"},
		{"everyone can read", "D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)", "grants access to S-1-1-0"},
		{"administrators", "D:P(A;;FA;;;" + me + ")(A;;FA;;;BA)", "grants access to S-1-5-32-544"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".key")
			if err := os.WriteFile(p, key, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.sddl != "" {
				setKeySecurity(t, p, tc.sddl)
			}
			if tc.want != "" {
				assertKeyRefused(t, p, tc.want)
				return
			}
			if _, err := LoadKey(p); err != nil {
				t.Fatalf("LoadKey: %v", err)
			}
		})
	}
}

// A symbolic link at the key path is opened as itself and refused, even
// when its target is a good key.
func TestLoadKeyWindowsRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := saveTestKey(t, dir, "real.key")
	link := filepath.Join(dir, "audit.key")
	symlinkOrSkip(t, target, link)
	assertKeyRefused(t, link, "reparse point")
}

// A key owned by another SID is refused: its owner keeps WRITE_DAC and can
// grant itself access. Needs elevation to set another owner.
func TestLoadKeyWindowsRefusesOtherOwner(t *testing.T) {
	p := saveTestKey(t, t.TempDir(), "audit.key")
	admins := wellKnown(t, windows.WinBuiltinAdministratorsSid)
	if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		needPrivilege(t, "cannot give the file another owner without elevation: %v", err)
	}
	assertKeyRefused(t, p, "is owned by S-1-5-32-544")
}
