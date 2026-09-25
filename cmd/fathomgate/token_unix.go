// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/fathomgate/fathomgate/internal/fileacl"
)

// readTokenFile reads a listen token file, refusing one another user could
// read or replace: the checks internal/audit applies to its key and log. It
// opens the file without following a final symbolic link (and without
// blocking on a FIFO), then checks the open descriptor: a regular file with
// exactly one link, owned by the effective user, with no group or other
// permission bits (mode 0600 or 0400), and on macOS no extended ACL. No
// error quotes the path.
func readTokenFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		// Linux and macOS return ELOOP for a final symlink, FreeBSD EMLINK.
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
			return nil, errors.New("the token file is a symbolic link; name the file itself")
		}
		return nil, fmt.Errorf("cannot open the token file: %w", pathless(err))
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot read the token file: %w", pathless(err))
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("the token file is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("the token file's owner cannot be checked")
	}
	// Nlink's type differs between platforms; the untyped constant needs
	// no conversion on any of them.
	if st.Nlink != 1 {
		return nil, fmt.Errorf("the token file has %d hard links; it must have exactly one", st.Nlink)
	}
	if euid := os.Geteuid(); uint64(st.Uid) != uint64(euid) { //nolint:gosec // euid is never negative on Unix
		return nil, fmt.Errorf("the token file is owned by uid %d, not the user running fathomgate (uid %d)", st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("the token file has mode %04o, so other users can read or change it; make it owner-only with chmod 600", perm)
	}
	// The mode bits do not show a macOS extended ACL (L2 in the security
	// review of PR #109); fileacl reads it on the open descriptor.
	switch ext, err := fileacl.Extended(f); {
	case err != nil:
		return nil, fmt.Errorf("cannot check the token file's access control list: %w", pathless(err))
	case ext:
		return nil, errors.New("the token file has an extended ACL, which can give other users access the mode does not show; remove it with chmod -N")
	}
	return readCapped(f)
}
