// SPDX-License-Identifier: Apache-2.0

//go:build aix || illumos || solaris

package main

import "errors"

// mkfifo is not available here: the syscall package has no Mkfifo on AIX,
// illumos or Solaris, so TestReadTokenFileUnix leaves out its named-pipe
// case.
func mkfifo(string) error { return errors.ErrUnsupported }
