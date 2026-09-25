// SPDX-License-Identifier: Apache-2.0

//go:build unix || windows

package main

import "github.com/fathomgate/fathomgate/internal/secretfile"

// readTokenFile reads a listen token file, refusing one another user could
// read or replace, with the owner-only checks internal/secretfile applies
// to every secret file (the audit signing key too, ADR 0028): not a
// symbolic link or other reparse point, a regular file with exactly one
// link, owned by the current user, mode 0600 or 0400 and no macOS extended
// ACL on Unix, a protected owner-only DACL on Windows. No error quotes the
// path, which may be a token typed in the wrong place.
func readTokenFile(path string) ([]byte, error) {
	return secretfile.Read(path, "the token file", maxTokenFileBytes)
}
