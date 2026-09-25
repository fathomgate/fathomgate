// SPDX-License-Identifier: FSL-1.1-ALv2

// Package configfile reads the files that decide what fathomgate serve
// lets through (the policy, the inventory, the profiles) only when no one
// but their owner and the administrators can change them (security review
// of PR #171, M4). They are not secrets, so anyone may read them; the
// check is about integrity: a user who can edit the policy can allow
// anything.
//
// The checks run on the opened file, so the file checked is the file read:
//
//   - Unix: a regular file (a directory for CheckDir) owned by the
//     effective user or root, with no group or other write bit (mode &
//     0o022 == 0), and on macOS no extended ACL (internal/fileacl), which
//     could grant a write the mode does not show.
//   - Windows: a disk file or directory owned by the current user, SYSTEM
//     or the Administrators group, whose DACL has no allow entry granting
//     write, append, delete, change-permissions or take-ownership rights to
//     anyone else. Inherited entries count. Deny entries and inherit-only
//     entries are ignored. A missing DACL (everyone has full access) is
//     refused.
//   - Anything else: refused; the checks cannot be made.
//
// A symbolic link is followed (unlike internal/secretfile); the target is
// what is checked. The directories above the file are not checked: a
// residual recorded in the threat model.
package configfile

import (
	"errors"
	"fmt"
	"io"
)

// ErrUnsafe is matched (errors.Is) by every refusal: a file that exists
// but others can change.
var ErrUnsafe = errors.New("configfile: other users can change the file")

// Read returns the content of the file at path after the checks above.
// what names the file in errors (for example "the policy file p.yaml").
// A file longer than limit bytes is refused.
func Read(path, what string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("configfile: the size limit for %s is %d; it must be positive", what, limit)
	}
	f, err := open(path, what, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", what, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return b, nil
}

// CheckDir runs the checks above on the directory at path.
func CheckDir(path, what string) error {
	f, err := open(path, what, true)
	if err != nil {
		return err
	}
	return f.Close()
}

type refusal struct{ msg string }

func (r *refusal) Error() string { return r.msg }
func (r *refusal) Unwrap() error { return ErrUnsafe }

func refuse(format string, args ...any) error {
	return &refusal{msg: fmt.Sprintf(format, args...)}
}
