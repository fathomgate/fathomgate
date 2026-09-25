// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package configfile

import (
	"fmt"
	"os"
	"syscall"

	"github.com/fathomgate/fathomgate/internal/fileacl"
)

// open opens path and checks the open descriptor.
func open(path, what string, dir bool) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", what, err)
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
		return fmt.Errorf("cannot read %s: %w", what, err)
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
		return refuse("%s is owned by uid %d, not by the user running fathomgate (uid %d) or root, so its owner can change what fathomgate enforces", what, st.Uid, euid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return refuse("%s has mode %04o, so other users can change it; remove their write access with chmod go-w", what, perm)
	}
	switch ext, err := fileacl.Extended(f); {
	case err != nil:
		return refuse("cannot check the access control list of %s: %v", what, err)
	case ext:
		return refuse("%s has an extended ACL, which can let other users change it although the mode does not show it; remove it with chmod -N", what)
	}
	return nil
}
