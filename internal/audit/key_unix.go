//go:build !windows

package audit

import (
	"os"
)

// ownerOnlyMode is the permission set for the private key and the audit log.
const ownerOnlyMode os.FileMode = 0o600

// createOwnerOnly creates path exclusively (O_CREATE|O_EXCL, so an existing
// file or symlink fails with fs.ErrExist) and sets mode 0600 on the open
// descriptor. The explicit Chmod makes the result independent of the umask.
// flag adds the access mode (os.O_WRONLY, optionally os.O_APPEND).
func createOwnerOnly(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|os.O_CREATE|os.O_EXCL, ownerOnlyMode)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(ownerOnlyMode); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return f, nil
}

// openOwnerOnlyAppend opens an existing file for appending and corrects its
// mode to 0600 through the open descriptor. It fails if the file is missing
// or if the caller may not change its mode (not the owner).
func openOwnerOnlyAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(ownerOnlyMode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
