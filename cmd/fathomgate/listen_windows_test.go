// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// errFamilyMissing is the bind error of a host without IPv6.
var errFamilyMissing error = os.NewSyscallError("bind", windows.WSAEADDRNOTAVAIL)

func TestLoopbackFamilyMissingWindows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		errno syscall.Errno
		want  bool
	}{
		{windows.WSAEADDRNOTAVAIL, true},
		{windows.WSAEAFNOSUPPORT, true},
		{windows.WSAEPROTONOSUPPORT, true},
		// Must refuse to start.
		{windows.WSAEADDRINUSE, false},
		{windows.WSAEACCES, false},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			t.Parallel()
			if got := loopbackFamilyMissing(os.NewSyscallError("bind", tc.errno)); got != tc.want {
				t.Fatalf("loopbackFamilyMissing %v, want %v", got, tc.want)
			}
		})
	}
}
