// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package audit

import (
	"errors"
	"os"
)

// On platforms that are neither Unix nor Windows Fathomgate cannot make the
// key or the log owner-only, so it refuses to create or open them.

func createExclusive(string, int, bool) (*os.File, error) { return nil, errors.ErrUnsupported }

func removeCreated(*os.File, string) error { return errors.ErrUnsupported }

func openExistingLog(string) (*os.File, error) { return nil, errors.ErrUnsupported }

func restrictOpenFile(*os.File) error { return errors.ErrUnsupported }

// openPublicKey opens a public key for reading; it is not secret, so it
// needs none of the owner-only checks.
func openPublicKey(path string) (*os.File, error) { return os.Open(path) }
