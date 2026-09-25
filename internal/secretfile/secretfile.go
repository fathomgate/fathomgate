// SPDX-License-Identifier: FSL-1.1-ALv2

// Package secretfile reads a secret from a file only its owner can read or
// replace. It is the one owner-only check behind the listen token files
// (cmd/fathomgate, ADR 0016) and the audit signing key (internal/audit,
// ADR 0028), and the check the redaction key will use in M2.
//
// Read opens the file without following a final symbolic link (O_NOFOLLOW
// on Unix; FILE_FLAG_OPEN_REPARSE_POINT on Windows) and without blocking on
// a named pipe, then checks the open descriptor or handle, not the path, so
// the file checked is the file read:
//
//   - Unix: a regular file with exactly one link, owned by the effective
//     user, with no group or other permission bits (mode 0600 or 0400), and
//     on macOS no extended ACL (internal/fileacl).
//   - Windows: a disk file, not a directory or reparse point, with exactly
//     one link, owned by the current user, with a protected DACL (nothing
//     inherited from its folder) whose allow entries name only that user
//     and SYSTEM. Deny entries are allowed.
//   - Anything else: refused; the checks cannot be made.
//
// There is no way to skip a check. No error quotes the content, and none
// quotes the path unless the caller puts it in the name it passes.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
)

// ErrUnsafe is matched (errors.Is) by every refusal: a file that exists but
// fails a check. An error that does not match it means the file could not
// be opened or read at all, was longer than the limit, or the limit was not
// positive.
var ErrUnsafe = errors.New("secretfile: the file is not owner-only")

// Read returns the content of the secret file at path, refusing a file
// another user could read or replace (see the package comment). what names
// the file in every error message, for example "the token file"
// or "the signing key /etc/fathomgate/audit.key". A file longer than limit
// bytes is refused, and a limit of zero or less is an error.
func Read(path, what string, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("secretfile: the size limit for %s is %d; it must be positive", what, limit)
	}
	return read(path, what, limit)
}

// refusal is an error for a failed check. Its text is the message alone.
// It unwraps to ErrUnsafe and, when a system call or read failed during
// the check, to that cause too, so errors.Is matches either.
type refusal struct {
	msg   string
	cause error
}

// Error returns the message.
func (r *refusal) Error() string { return r.msg }

// Unwrap returns ErrUnsafe and the cause, if there is one.
func (r *refusal) Unwrap() []error {
	if r.cause == nil {
		return []error{ErrUnsafe}
	}
	return []error{ErrUnsafe, r.cause}
}

// refuse is a refusal with no underlying cause.
func refuse(format string, args ...any) error {
	return &refusal{msg: fmt.Sprintf(format, args...)}
}

// refuseCause is a refusal caused by err, which the message should
// describe with %v; errors.Is(result, err) holds.
func refuseCause(err error, format string, args ...any) error {
	return &refusal{msg: fmt.Sprintf(format, args...), cause: err}
}

// readCapped reads at most limit bytes from r, and fails if there is more.
func readCapped(r io.Reader, what string, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", what, pathless(err))
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", what, limit)
	}
	return b, nil
}

// pathless strips the path from a *fs.PathError, so an error never quotes
// the path, which may be a secret typed in the wrong place.
func pathless(err error) error {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		return pe.Err
	}
	return err
}
