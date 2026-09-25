// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// currentSID is the SID of the user running the test, as SDDL.
func currentSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// setSecurity gives path the current user as owner and the DACL in sddl,
// protected when sddl starts with "D:P".
func setSecurity(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("O:" + currentSID(t) + sddl)
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

// writeOwnerOnly writes a token file readTokenFile accepts: owned by the
// current user, with a protected DACL granting only that user.
func writeOwnerOnly(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	setSecurity(t, path, "D:P(A;;FA;;;"+currentSID(t)+")")
}

// makeShared grants every user read access to a token file.
func makeShared(t *testing.T, path string) {
	t.Helper()
	setSecurity(t, path, "D:P(A;;FA;;;"+currentSID(t)+")(A;;FR;;;BU)")
}

func TestReadTokenFileWindows(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	me := currentSID(t)
	tok := []byte(testListenToken + "\r\n")
	for _, tc := range []struct {
		name string
		sddl string // "" leaves what the folder gives the file
		want string // "" accepts
	}{
		{"owner only", "D:P(A;;FA;;;" + me + ")", ""},
		{"owner and SYSTEM", "D:P(A;;FA;;;" + me + ")(A;;FA;;;SY)", ""},
		{"deny entries are fine", "D:P(D;;FA;;;BG)(A;;FA;;;" + me + ")", ""},
		{"inherited", "", "inherits permissions from its folder"},
		{"unprotected", "D:(A;;FA;;;" + me + ")", "inherits permissions from its folder"},
		{"users can read", "D:P(A;;FA;;;" + me + ")(A;;FR;;;BU)", "grants access to S-1-5-32-545"},
		{"everyone can read", "D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)", "grants access to S-1-1-0"},
		{"administrators", "D:P(A;;FA;;;" + me + ")(A;;FA;;;BA)", "grants access to S-1-5-32-544"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.WriteFile(path, tok, 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.sddl != "" {
				setSecurity(t, path, tc.sddl)
			}
			got, err := readTokenFile(path)
			switch {
			case tc.want == "" && err != nil:
				t.Error(err)
			case tc.want == "" && string(got) != string(tok):
				t.Errorf("read %q", got)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), dir) {
				t.Errorf("the error quotes the path: %v", err)
			}
		})
	}

	target := filepath.Join(dir, "target")
	writeOwnerOnly(t, target, tok)
	hard := filepath.Join(dir, "hard")
	if err := os.Link(target, hard); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, path, want string }{
		{"hard link", hard, "2 hard links"},
		{"directory", dir, "cannot open the token file"},
		{"missing", filepath.Join(dir, "no-such-file"), "cannot open the token file"},
	}
	// A symbolic link needs a privilege or developer mode.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err == nil {
		cases = append(cases, struct{ name, path, want string }{"symbolic link", link, "reparse point"})
	} else {
		t.Logf("symbolic link case skipped: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := readTokenFile(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), dir) {
				t.Errorf("the error quotes the path: %v", err)
			}
		})
	}
}
