// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix && !aix && !illumos && !solaris

package main

import "syscall"

// mkfifo makes a named pipe for TestReadTokenFileUnix.
func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
