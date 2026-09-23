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

// Same share mode os.OpenFile uses, so Verify can read a log a Writer holds.
const shareMode = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE

// ownerOnlySDDL returns the security descriptor for the private key and the
// audit log: owned by the current user, with a protected DACL ("D:P", no
// inherited ACEs) that grants full access to the current user and to
// LocalSystem only. Administrators are deliberately not granted: an
// administrator can still take ownership, but has to do so explicitly.
func ownerOnlySDDL() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("current user: %w", err)
	}
	sid := u.User.Sid.String()
	return "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)", nil
}

// createOwnerOnly creates path with CREATE_NEW (an existing file fails with
// fs.ErrExist) and the owner-only security descriptor applied atomically by
// CreateFile, so there is no moment at which another user could open it.
// flag carries os.O_APPEND for the log; anything else opens for writing.
// The handle is not inheritable.
func createOwnerOnly(path string, flag int) (*os.File, error) {
	sddl, err := ownerOnlySDDL()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	access := uint32(windows.GENERIC_WRITE)
	if flag&os.O_APPEND != 0 {
		access = appendAccess
	}
	return createFile(path, access, sa, windows.CREATE_NEW)
}

// openOwnerOnlyAppend opens an existing file for appending and replaces its
// DACL with the protected owner-only DACL, removing inherited and explicit
// entries for anyone else. The owner is left as it is.
func openOwnerOnlyAppend(path string) (*os.File, error) {
	sddl, err := ownerOnlySDDL()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	f, err := createFile(path, appendAccess|windows.WRITE_DAC, nil, windows.OPEN_EXISTING)
	if err != nil {
		return nil, err
	}
	err = windows.SetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	if err != nil {
		_ = f.Close()
		return nil, &fs.PathError{Op: "set DACL", Path: path, Err: err}
	}
	return f, nil
}

func createFile(path string, access uint32, sa *windows.SecurityAttributes, disposition uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name, access, shareMode, sa, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
