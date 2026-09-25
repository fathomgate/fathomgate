// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/fathomgate/fathomgate/internal/fileacl"
)

func read(path, what string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// Linux and macOS return ELOOP for a final symlink, FreeBSD EMLINK.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, refuse("%s is a symbolic link; name the file itself", what)
		}
		return nil, fmt.Errorf("cannot open %s: %w", what, pathless(err))
	}
	defer func() { _ = f.Close() }()
	if err := check(f, what); err != nil {
		return nil, err
	}
	return readCapped(f, what, limit)
}

// check runs Read's checks on the open descriptor.
func check(f *os.File, what string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", what, pathless(err))
	}
	if !fi.Mode().IsRegular() {
		return refuse("%s is not a regular file", what)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return refuse("the owner of %s cannot be checked", what)
	}
	// Nlink's type differs between platforms; the untyped constant needs
	// no conversion on any of them.
	if st.Nlink != 1 {
		return refuse("%s has %d hard links; it must have exactly one", what, st.Nlink)
	}
	if euid := os.Geteuid(); uint64(st.Uid) != uint64(euid) { //nolint:gosec // euid is never negative on Unix
		return refuse("%s is owned by uid %d, not the user running fathomgate (uid %d)", what, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return refuse("%s has mode %04o, so other users can read or change it; make it owner-only with chmod 600", what, perm)
	}
	// The mode bits do not show a macOS extended ACL (L2 in the security
	// review of PR #109); fileacl reads it on the open descriptor.
	switch ext, err := fileacl.Extended(f); {
	case err != nil:
		return refuseCause(err, "cannot check the access control list of %s: %v", what, pathless(err))
	case ext:
		return refuse("%s has an extended ACL, which can give other users access the mode does not show; remove it with chmod -N", what)
	}
	return nil
}
