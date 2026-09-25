// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package secretfile

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func read(path, what string, limit int64) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("the path of %s contains a NUL character", what)
	}
	// Share mode FILE_SHARE_READ: nobody can write, rename or delete the
	// file while it is open here. SECURITY_SQOS_PRESENT with
	// SECURITY_IDENTIFICATION: if the path names a named pipe (\\.\pipe\...,
	// or a UNC path to one on another host), its server can identify this process but not
	// impersonate it, before the disk-file check below refuses the handle.
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", what, err)
	}
	f := os.NewFile(uintptr(h), "secret file")
	defer func() { _ = f.Close() }()
	if err := check(h, what); err != nil {
		return nil, err
	}
	return readCapped(f, what, limit)
}

// check runs Read's checks on an open handle.
func check(h windows.Handle, what string) error {
	typ, err := windows.GetFileType(h)
	if err != nil {
		return fmt.Errorf("cannot check %s: %w", what, err)
	}
	if typ != windows.FILE_TYPE_DISK {
		return refuse("%s is not a disk file", what)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("cannot check %s: %w", what, err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return refuse("%s is a symbolic link, junction or other reparse point; name the file itself", what)
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return refuse("%s is a directory", what)
	case info.NumberOfLinks != 1:
		return refuse("%s has %d hard links; it must have exactly one", what, info.NumberOfLinks)
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the permissions of %s: %w", what, err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot identify the current user: %w", err)
	}
	user := me.User.Sid
	owner, _, err := sd.Owner()
	if err != nil {
		return refuseCause(err, "the owner of %s cannot be read: %v", what, err)
	}
	if owner == nil {
		return refuse("the owner of %s cannot be read", what)
	}
	if !owner.Equals(user) {
		return refuse(`%s is owned by %v, not the user running fathomgate (%v); if you trust the file, take it with: icacls <file> /setowner "%%USERNAME%%"`, what, owner, user)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the permissions of %s: %w", what, err)
	}
	const fix = `; make it owner-only with: icacls <file> /inheritance:r /grant:r "%USERNAME%:F"`
	if control&windows.SE_DACL_PROTECTED == 0 {
		return refuse("%s inherits permissions from its folder%s", what, fix)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return refuseCause(err, "the access control list of %s cannot be read: %v%s", what, err, fix)
	}
	if dacl == nil {
		return refuse("%s has no access control list, so everyone can open it%s", what, fix)
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return refuseCause(err, "cannot read the permissions of %s: %v", what, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// The SID starts at SidStart and runs to the end of the ACE, as
			// GetAce lays it out; x/sys/windows reads ACEs the same way.
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // reading an ACE's SID in place
			if sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) {
				continue
			}
			return refuse("%s grants access to %v; only its owner and SYSTEM may have access%s", what, sid, fix)
		default:
			return refuse("the access control list of %s has an entry of type %d, which fathomgate does not accept%s", what, ace.Header.AceType, fix)
		}
	}
	return nil
}
