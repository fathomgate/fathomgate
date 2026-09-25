// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeRights are the access rights that let a holder change what the
// file or directory says: write or append data (for a directory: add a
// file or subdirectory), delete it or a child, change its permissions or
// owner, and the generic rights that include those.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 /* FILE_DELETE_CHILD */ |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// dirClause ends every refusal: fixing the file is not enough if others can
// write the directory that holds it (the parent directories are not
// checked; threat model).
const dirClause = `. Users who can write the directory that holds it can still replace it, so keep policies in a directory only you and Administrators can write, such as %USERPROFILE%\.config\fathomgate, or C:\ProgramData\fathomgate writable only by Administrators and SYSTEM`

// open opens path and checks the open handle. os.Open asks for
// GENERIC_READ, which includes READ_CONTROL, and opens a directory too.
func open(path, what string, dir bool) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", what, err)
	}
	if err := check(f, path, what, dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func check(f *os.File, path, what string, dir bool) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", what, err)
	}
	switch {
	case dir && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", what)
	case !dir && fi.IsDir():
		return fmt.Errorf("%s is a directory", what)
	}
	h := windows.Handle(f.Fd())
	if !dir {
		typ, err := windows.GetFileType(h)
		if err != nil {
			return fmt.Errorf("cannot check %s: %w", what, err)
		}
		if typ != windows.FILE_TYPE_DISK {
			return refuse("%s is not a disk file", what)
		}
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return refuseCause(err, "cannot read the permissions of %s: %v", what, err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot identify the current user: %w", err)
	}
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(me.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return refuse("the owner of %s cannot be read", what)
	}
	fix := fixCommand(path, dir)
	if !trusted(owner) {
		return refuse(`%s is owned by %s, not by the user running fathomgate (%s), SYSTEM or Administrators, so its owner can change what fathomgate enforces; if you trust the file, take it with: icacls "%s" /setowner "%%USERNAME%%", then run in Command Prompt: %s%s`,
			what, account(owner), account(me.User.Sid), path, fix, dirClause)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return refuseCause(err, "the access control list of %s cannot be read: %v", what, err)
	}
	if dacl == nil {
		return refuse("%s has no access control list, so everyone can change it; run in Command Prompt: %s%s", what, fix, dirClause)
	}
	// Every account that can write, each named once, so one run of the
	// fix command is enough.
	var writers, writerSIDs []string
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return refuseCause(err, "cannot read the permissions of %s: %v", what, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // applies to children only, not to this object
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ace.Mask&writeRights == 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // reading an ACE's SID in place
			// The owner passed trusted above, so trusted covers it too.
			if trusted(sid) {
				continue
			}
			if name := account(sid); !slices.Contains(writers, name) {
				writers = append(writers, name)
				writerSIDs = append(writerSIDs, "*"+sid.String())
			}
		default:
			return refuse("the access control list of %s has an entry of type %d, which fathomgate does not accept; run in Command Prompt: %s%s", what, ace.Header.AceType, fix, dirClause)
		}
	}
	if len(writers) > 0 {
		// /grant:r replaces only the named accounts' explicit entries, so
		// the others' are removed by SID (names are localised).
		fix += fmt.Sprintf(` && icacls "%s" /remove:g %s`, path, strings.Join(writerSIDs, " "))
		return refuse("%s can be changed by %s; only its owner, SYSTEM and Administrators may change it; run in Command Prompt: %s%s", what, strings.Join(writers, ", "), fix, dirClause)
	}
	return nil
}

// fixCommand is a runnable icacls command that leaves path with the
// current user, SYSTEM and Administrators only (for a directory, inherited
// by what it holds).
func fixCommand(path string, dir bool) string {
	inherit := ""
	if dir {
		inherit = "(OI)(CI)"
	}
	return fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "%%USERNAME%%:%sF" SYSTEM:%sF Administrators:%sF`, path, inherit, inherit, inherit)
}

// account names sid as DOMAIN\name, or as its SID string when the name
// cannot be looked up.
func account(sid *windows.SID) string {
	name, domain, _, err := sid.LookupAccount("")
	if err != nil || name == "" {
		return sid.String()
	}
	if domain == "" {
		return name
	}
	return domain + `\` + name
}
