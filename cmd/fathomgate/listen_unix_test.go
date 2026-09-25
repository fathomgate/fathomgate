// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"os"
	"syscall"
	"testing"
)

// errFamilyMissing is the bind error of a host without IPv6 on lo.
var errFamilyMissing error = os.NewSyscallError("bind", syscall.EADDRNOTAVAIL)

func TestLoopbackFamilyMissingUnix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		errno syscall.Errno
		want  bool
	}{
		{syscall.EADDRNOTAVAIL, true},
		{syscall.EAFNOSUPPORT, true},
		{syscall.EPROTONOSUPPORT, true},
		// Must refuse to start.
		{syscall.EADDRINUSE, false},
		{syscall.EACCES, false},
		{syscall.EPERM, false},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			t.Parallel()
			if got := loopbackFamilyMissing(os.NewSyscallError("bind", tc.errno)); got != tc.want {
				t.Fatalf("loopbackFamilyMissing %v, want %v", got, tc.want)
			}
		})
	}
}
