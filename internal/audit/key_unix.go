// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/fathomgate/fathomgate/internal/fileacl"
)

const (
	// ownerOnlyMode is the mode of the private key and the audit log.
	ownerOnlyMode os.FileMode = 0o600
	// publicMode is the mode of the public key: readable by verifiers.
	publicMode os.FileMode = 0o644
)

// createExclusive creates path with O_CREATE|O_EXCL, so an existing file or
// symlink (even a dangling one) fails with fs.ErrExist and is never
// followed, then sets the mode on the open descriptor so the umask cannot
// change it. flag carries the access mode (O_WRONLY, or O_RDWR|O_APPEND).
// An owner-only file that came out with an extended ACL (on macOS, entries
// inherited from the folder, which chmod does not remove) is deleted and
// refused: the mode would not show the access it grants (L2 in the
// security review of PR #109).
func createExclusive(path string, flag int, ownerOnly bool) (*os.File, error) {
	mode := publicMode
	if ownerOnly {
		mode = ownerOnlyMode
	}
	f, err := os.OpenFile(path, flag|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		discard(f, path)
		return nil, err
	}
	if ownerOnly {
		if err := refuseExtendedACL(f, path); err != nil {
			discard(f, path)
			return nil, err
		}
	}
	return f, nil
}

// refuseExtendedACL returns an error when f has an extended ACL or its ACL
// cannot be read (fileacl; macOS only).
func refuseExtendedACL(f *os.File, path string) error {
	switch ext, err := fileacl.Extended(f); {
	case err != nil:
		return fmt.Errorf("%s: cannot check the access control list: %w", path, err)
	case ext:
		return fmt.Errorf("%s has an extended ACL (inherited from its folder, or set with chmod +a), which can give other users access the mode does not show; remove it with chmod -N, and the folder's inheritable entries with chmod -N on the folder", path)
	}
	return nil
}

// removeCreated unlinks path only if it is still the file f refers to (same
// device and inode). There is a residual window between the Lstat and the
// unlink; only someone with write access to the directory can swap the
// entry in that window, and they could delete that entry themselves.
func removeCreated(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	li, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(fi, li) {
		return fmt.Errorf("%s no longer refers to the file created; not removing it", path)
	}
	return os.Remove(path)
}

// openExistingLog opens an existing log for reading and appending with
// O_NOFOLLOW, then checks the open descriptor: it must be a regular file
// with exactly one link, owned by the effective user. Nothing about the
// file is changed here; restrictOpenFile runs only after the chain verifies.
func openExistingLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// Linux and macOS return ELOOP for a final symlink, FreeBSD EMLINK.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, fmt.Errorf("%w: %s is a symbolic link", errUnsafeLog, path)
		}
		return nil, err
	}
	if err := checkLogFile(f, path); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func checkLogFile(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file (%v)", errUnsafeLog, path, fi.Mode().Type())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s: no ownership information", errUnsafeLog, path)
	}
	// Nlink is uint16 (darwin), uint32 (linux/arm64) or uint64 (linux/amd64);
	// comparing with the untyped constant 1 needs no conversion on any of them.
	if st.Nlink != 1 {
		return fmt.Errorf("%w: %s has %d hard links", errUnsafeLog, path, st.Nlink)
	}
	if euid := os.Geteuid(); uint64(st.Uid) != uint64(euid) { //nolint:gosec // euid is never negative on Unix
		return fmt.Errorf("%w: %s is owned by uid %d, not the current user (uid %d)", errUnsafeLog, path, st.Uid, euid)
	}
	// restrictOpenFile resets the mode, but not an extended ACL.
	if err := refuseExtendedACL(f, path); err != nil {
		return fmt.Errorf("%w: %w", errUnsafeLog, err)
	}
	return nil
}

// openPublicKey opens a public key for reading with O_NONBLOCK, so a FIFO
// at the path cannot block the verifier; LoadPublicKey then refuses
// anything but a regular file on the open descriptor.
func openPublicKey(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// restrictOpenFile sets mode 0600 through the open descriptor.
func restrictOpenFile(f *os.File) error {
	return f.Chmod(ownerOnlyMode)
}
