// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package configfile

import (
	"fmt"
	"os"
	"syscall"

	"github.com/fathomgate/fathomgate/internal/fileacl"
)

// unixDirClause ends the permission refusals: fixing the file is not
// enough if others can write the directory that holds it.
const unixDirClause = ". Users who can write the directory that holds it can still replace it, so keep these files in a directory only you can write, such as ~/.config/fathomgate at mode 0700"

// open opens path and checks the open descriptor.
func open(path, what string, dir bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", what, withoutPath(err))
	}
	if err := check(f, what, dir, os.Geteuid()); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// check runs the Unix checks on f for the effective user euid.
func check(f *os.File, what string, dir bool, euid int) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot read %s: %w", what, withoutPath(err))
	}
	switch {
	case dir && !fi.IsDir():
		return fmt.Errorf("%s is not a directory", what)
	case !dir && fi.IsDir():
		return fmt.Errorf("%s is a directory", what)
	case !dir && !fi.Mode().IsRegular():
		return refuse("%s is not a regular file", what)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return refuse("the owner of %s cannot be checked", what)
	}
	if uint64(st.Uid) != uint64(euid) && st.Uid != 0 { //nolint:gosec // euid is never negative on Unix
		return refuse("%s is owned by uid %d, not by the user running fathomgate (uid %d) or root, so its owner can change what fathomgate enforces%s", what, st.Uid, euid, unixDirClause)
	}
	// On Linux a POSIX ACL entry that grants a named user or group write
	// raises the ACL mask, and the mask is what stat reports as the group
	// bits, so such a file shows g+w here and is refused
	// (TestLinuxPOSIXACLWrite). macOS ACLs are not in the mode; fileacl
	// reads them below.
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return refuse("%s has mode %04o, so other users can change it; remove their write access with chmod go-w%s", what, perm, unixDirClause)
	}
	switch ext, err := fileacl.Extended(f); {
	case err != nil:
		return refuseCause(err, "cannot check the access control list of %s: %v", what, err)
	case ext:
		return refuse("%s has an extended ACL, which can let other users change it although the mode does not show it; remove it with chmod -N", what)
	}
	return nil
}
