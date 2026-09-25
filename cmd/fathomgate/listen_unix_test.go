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
	for _, errno := range []syscall.Errno{syscall.EADDRNOTAVAIL, syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT} {
		if !loopbackFamilyMissing(os.NewSyscallError("bind", errno)) {
			t.Errorf("%v not taken as a missing loopback family", errno)
		}
	}
	for _, errno := range []syscall.Errno{syscall.EADDRINUSE, syscall.EACCES, syscall.EPERM} {
		if loopbackFamilyMissing(os.NewSyscallError("bind", errno)) {
			t.Errorf("%v taken as a missing loopback family; it must refuse to start", errno)
		}
	}
}
