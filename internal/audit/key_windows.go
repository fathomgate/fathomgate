// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package audit

import (
	"fmt"
	"io/fs"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Access for an append-only handle, as syscall.Open builds it for O_APPEND:
// everything GENERIC_WRITE grants except FILE_WRITE_DATA, so every write
// lands at the end of the file.
const appendAccess = windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_WRITE_EA | windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE //nolint:misspell // Windows API name

// Same share mode os.OpenFile uses: no FILE_SHARE_DELETE, so the path of a
// file we hold open cannot be renamed, replaced or deleted underneath us.
const shareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE

// currentUserSID is the user of the process token.
func currentUserSID() (*windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("current user: %w", err)
	}
	return u.User.Sid, nil
}

// ownerOnlySD returns the security descriptor for the private key and the
// audit log: owned by the current user, with a protected DACL ("D:P", no
// inherited ACEs) that grants full access to the current user and to
// LocalSystem only. Administrators are deliberately not granted: backup
// through SeBackupPrivilege still works, and recovery is by taking
// ownership, which is explicit and visible.
func ownerOnlySD() (*windows.SECURITY_DESCRIPTOR, error) {
	me, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	sid := me.String()
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)")
}

// createExclusive creates path with CREATE_NEW plus
// FILE_FLAG_OPEN_REPARSE_POINT, as syscall.Open does for O_CREAT|O_EXCL.
// Without that flag CREATE_NEW follows a dangling symlink and creates the
// file at the link's target, which an attacker who can plant links in the
// directory would choose. With it, any existing entry at path (file,
// directory, symlink, dangling or not, or junction) fails and nothing is
// created elsewhere. With
// ownerOnly the owner-only descriptor is applied atomically by CreateFile,
// so there is no moment at which another user could open the file; without
// it the file inherits its folder's ACL (the public key). flag carries
// os.O_APPEND for the log, which is then opened for read and append. The
// handle has DELETE access so removeCreated can delete through it, and is
// not inheritable.
func createExclusive(path string, flag int, ownerOnly bool) (*os.File, error) {
	var sa *windows.SecurityAttributes
	if ownerOnly {
		sd, err := ownerOnlySD()
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: path, Err: err}
		}
		sa = &windows.SecurityAttributes{SecurityDescriptor: sd}
		sa.Length = uint32(unsafe.Sizeof(*sa))
	}
	access := uint32(windows.GENERIC_WRITE)
	if flag&os.O_APPEND != 0 {
		access = windows.GENERIC_READ | appendAccess
	}
	return createFile(path, access|windows.DELETE, sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT)
}

// removeCreated marks the file behind f for deletion; it is removed when f
// is closed. Deleting through the handle cannot hit a different file that
// was swapped in at path.
func removeCreated(f *os.File, _ string) error {
	deleteFile := byte(1) // FILE_DISPOSITION_INFO{DeleteFile: TRUE}
	return windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &deleteFile, 1)
}

// openExistingLog opens an existing log for reading and appending with
// FILE_FLAG_OPEN_REPARSE_POINT, so a symlink, junction or mount point is
// opened as itself rather than followed, then checks the handle: a disk
// file, not a directory or reparse point, exactly one link, owned by the
// current user. A file owned by someone else is refused because its owner
// keeps implicit WRITE_DAC and could re-grant access after any DACL reset.
// Nothing about the file is changed here.
func openExistingLog(path string) (*os.File, error) {
	f, err := createFile(path, windows.GENERIC_READ|appendAccess|windows.READ_CONTROL|windows.WRITE_DAC,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return nil, err
	}
	if err := checkLogFile(windows.Handle(f.Fd()), path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func checkLogFile(h windows.Handle, path string) error {
	typ, err := windows.GetFileType(h)
	if err != nil {
		return &fs.PathError{Op: "GetFileType", Path: path, Err: err}
	}
	if typ != windows.FILE_TYPE_DISK {
		return fmt.Errorf("%w: %s is not a disk file", errUnsafeLog, path)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return &fs.PathError{Op: "GetFileInformationByHandle", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: %s is a symbolic link, junction or other reparse point", errUnsafeLog, path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fmt.Errorf("%w: %s is a directory", errUnsafeLog, path)
	}
	if info.NumberOfLinks != 1 {
		return fmt.Errorf("%w: %s has %d hard links", errUnsafeLog, path, info.NumberOfLinks)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return &fs.PathError{Op: "GetSecurityInfo", Path: path, Err: err}
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return &fs.PathError{Op: "GetSecurityInfo", Path: path, Err: err}
	}
	me, err := currentUserSID()
	if err != nil {
		return &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if owner == nil || !owner.Equals(me) {
		return fmt.Errorf("%w: %s is owned by %v, not the current user %v", errUnsafeLog, path, owner, me)
	}
	return nil
}

// openPublicKey opens a public key for reading. SECURITY_SQOS_PRESENT with
// SECURITY_IDENTIFICATION: if the path names a named pipe, its server can
// identify this process but not impersonate it; LoadPublicKey then refuses
// anything but a regular file on the open handle.
func openPublicKey(path string) (*os.File, error) {
	return createFile(path, windows.GENERIC_READ, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION)
}

// restrictOpenFile replaces the DACL of an open log with the protected
// owner-only DACL, removing inherited and explicit entries for anyone else.
// The handle must have WRITE_DAC (openExistingLog asks for it).
func restrictOpenFile(f *os.File) error {
	sd, err := ownerOnlySD()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
}

// createFile wraps CreateFile with the share mode above. Paths longer than
// MAX_PATH are not given the \\?\ prefix, so they fail (closed); tracked as
// a follow-up in the T0.12 handoff.
func createFile(path string, access uint32, sa *windows.SecurityAttributes, disposition, flags uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name, access, shareMode, sa, disposition, windows.FILE_ATTRIBUTE_NORMAL|flags, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
