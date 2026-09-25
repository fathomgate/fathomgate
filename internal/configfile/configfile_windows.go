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

// withDir appends dirText to advice: after a sentence, or on its own line
// after commands printed one per line.
func withDir(advice string) string {
	if strings.HasSuffix(advice, "\n") {
		return advice + dirText
	}
	return advice + ". " + dirText
}

// dirText ends every refusal: fixing the file is not enough if others can
// write the directory that holds it (the parent directories are not
// checked; threat model).
const dirText = `Users who can write the directory that holds it can still replace it, so keep these files in a directory only you and Administrators can write, such as %USERPROFILE%\.config\fathomgate, or C:\ProgramData\fathomgate writable only by Administrators and SYSTEM`

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
	user := me.User.Sid
	trusted := func(sid *windows.SID) bool {
		return sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return refuse("the owner of %s cannot be read", what)
	}
	if !trusted(owner) {
		// No command: taking ownership needs an administrator, and the next
		// start prints the permission fix if one is still needed.
		return refuse("%s is owned by %s, not by the user running fathomgate (%s), SYSTEM or Administrators, so its owner can change what fathomgate enforces; if you trust the file, have an administrator make you its owner (icacls /setowner) and start fathomgate again. %s",
			what, account(owner), account(user), dirText)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return refuseCause(err, "the access control list of %s cannot be read: %v", what, err)
	}
	if dacl == nil {
		return refuse("%s has no access control list, so everyone can change it; %s", what, withDir(fixAdvice(path, dir, user, nil)))
	}
	// Every account that can write, each named once, so one fix is enough.
	// explicit are the SIDs of the non-inherited entries among them: those
	// are what /inheritance:r leaves behind.
	var writers, explicit []string
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
			}
			if s := `"*` + sid.String() + `"`; ace.Header.AceFlags&windows.INHERITED_ACE == 0 && !slices.Contains(explicit, s) {
				explicit = append(explicit, s)
			}
		default:
			return refuse("the access control list of %s has an entry of type %d, which fathomgate does not accept; %s", what, ace.Header.AceType, withDir(fixAdvice(path, dir, user, nil)))
		}
	}
	if len(writers) > 0 {
		return refuse("%s can be changed by %s; only its owner, SYSTEM and Administrators may change it; %s", what, strings.Join(writers, ", "), withDir(fixAdvice(path, dir, user, explicit)))
	}
	return nil
}

// fixAdvice is the fix to print. Its first command removes inherited
// entries and grants the current user, SYSTEM and Administrators full
// control (for a directory, inherited by what it holds), naming each by
// SID, so it runs unchanged in Command Prompt and in PowerShell. explicit
// are the SIDs of the offending non-inherited entries, which /grant:r
// leaves in place; a second command removes them. Each command is on a
// line of its own (PowerShell 5.1 has no &&, and nothing may follow a
// command on its line). A path holding a character a shell would change
// (%, !, a control character, a quote) gets prose instead of a command.
func fixAdvice(path string, dir bool, user *windows.SID, explicit []string) string {
	if !safeForCommand(path) {
		return "remove every other account's write access with icacls /inheritance:r and /grant:r (no command is printed, because the path holds a character a command line would change)"
	}
	inherit := ""
	if dir {
		inherit = "(OI)(CI)"
	}
	grant := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "*%s:%sF" "*S-1-5-18:%sF" "*S-1-5-32-544:%sF"`, path, user, inherit, inherit, inherit)
	if len(explicit) == 0 {
		return "run:\n  " + grant + "\n"
	}
	return fmt.Sprintf("run these two commands:\n  %s\n  icacls \"%s\" /remove:g %s\n", grant, path, strings.Join(explicit, " "))
}

// safeForCommand reports whether path can be put between double quotes on
// a Command Prompt or PowerShell line and reach icacls unchanged.
func safeForCommand(path string) bool {
	return !strings.ContainsFunc(path, func(r rune) bool {
		return r == '%' || r == '!' || r == '"' || r == '$' || r == '`' || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)
	})
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
