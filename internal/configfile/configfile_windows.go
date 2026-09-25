// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package configfile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeRights are the access rights that let a holder change what the
// file or directory says: write or append data (for a directory: add a
// file or subdirectory), delete it or a child, change its permissions or
// owner, and the generic rights that include those.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | 0x40 /* FILE_DELETE_CHILD */ |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// open opens path and checks the open handle. os.Open asks for
// GENERIC_READ, which includes READ_CONTROL, and opens a directory too.
func open(path, what string, dir bool) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", what, err)
	}
	if err := check(f, what, dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func check(f *os.File, what string, dir bool) error {
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
		return refuse("cannot read the permissions of %s: %v", what, err)
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
	if !trusted(owner) {
		return refuse(`%s is owned by %v, not by the user running fathomgate (%v), SYSTEM or Administrators, so its owner can change what fathomgate enforces; if you trust the file, take it with: icacls <file> /setowner "%%USERNAME%%"`, what, owner, me.User.Sid)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return refuse("the access control list of %s cannot be read: %v", what, err)
	}
	if dacl == nil {
		return refuse("%s has no access control list, so everyone can change it", what)
	}
	const fix = `; remove their write access, for example with: icacls <file> /inheritance:d /remove:g <name>`
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return refuse("cannot read the permissions of %s: %v", what, err)
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
			if trusted(sid) || sid.Equals(owner) {
				continue
			}
			return refuse("%s lets %v change it; only its owner, SYSTEM and Administrators may%s", what, sid, fix)
		default:
			return refuse("the access control list of %s has an entry of type %d, which fathomgate does not accept", what, ace.Header.AceType)
		}
	}
	return nil
}
