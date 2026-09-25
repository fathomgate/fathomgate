// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readTokenFile reads a listen token file, refusing one another user could
// read or replace: the checks internal/audit applies to its key and log. It
// opens the file itself, not what a symbolic link, junction or other
// reparse point names, then checks the handle: a disk file, not a directory
// or reparse point, with exactly one link, owned by the current user, with
// a protected DACL (no entries inherited from its folder) whose allow
// entries name only the current user and SYSTEM. Deny entries are allowed.
// No error quotes the path.
func readTokenFile(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("the token file path contains a NUL character")
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open the token file: %w", err)
	}
	f := os.NewFile(uintptr(h), "token file")
	defer func() { _ = f.Close() }()
	if err := checkTokenHandle(h); err != nil {
		return nil, err
	}
	return readCapped(f)
}

// checkTokenHandle runs readTokenFile's checks on an open handle.
func checkTokenHandle(h windows.Handle) error {
	typ, err := windows.GetFileType(h)
	if err != nil {
		return fmt.Errorf("cannot check the token file: %w", err)
	}
	if typ != windows.FILE_TYPE_DISK {
		return errors.New("the token file is not a disk file")
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("cannot check the token file: %w", err)
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return errors.New("the token file is a symbolic link, junction or other reparse point; name the file itself")
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return errors.New("the token file is a directory")
	case info.NumberOfLinks != 1:
		return fmt.Errorf("the token file has %d hard links; it must have exactly one", info.NumberOfLinks)
	}

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("cannot read the token file's permissions: %w", err)
	}
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("cannot identify the current user: %w", err)
	}
	user := me.User.Sid
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("the token file's owner cannot be read")
	}
	if !owner.Equals(user) {
		return fmt.Errorf("the token file is owned by %v, not the user running fathomgate (%v)", owner, user)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("cannot read the token file's permissions: %w", err)
	}
	const fix = `; make it owner-only with: icacls <file> /inheritance:r /grant:r "%USERNAME%:F"`
	if control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("the token file inherits permissions from its folder" + fix)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("the token file has no access control list, so everyone can open it" + fix)
	}
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("cannot read the token file's permissions: %w", err)
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
			return fmt.Errorf("the token file grants access to %v; only its owner and SYSTEM may have access%s", sid, fix)
		default:
			return fmt.Errorf("the token file's access control list has an entry of type %d, which fathomgate does not accept%s", ace.Header.AceType, fix)
		}
	}
	return nil
}
