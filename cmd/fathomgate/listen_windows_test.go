// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"syscall"
	"testing"
)

// errFamilyMissing is the bind error of a host without IPv6.
var errFamilyMissing error = os.NewSyscallError("bind", wsaeAddrNotAvail)

func TestLoopbackFamilyMissingWindows(t *testing.T) {
	t.Parallel()
	for _, errno := range []syscall.Errno{wsaeAddrNotAvail, wsaeAFNoSupport, wsaeProtoNoSupport} {
		if !loopbackFamilyMissing(os.NewSyscallError("bind", errno)) {
			t.Errorf("%v not taken as a missing loopback family", errno)
		}
	}
	// WSAEADDRINUSE, WSAEACCES.
	for _, errno := range []syscall.Errno{10048, 10013} {
		if loopbackFamilyMissing(os.NewSyscallError("bind", errno)) {
			t.Errorf("%v taken as a missing loopback family; it must refuse to start", errno)
		}
	}
}
