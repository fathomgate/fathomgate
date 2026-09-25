// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// loopbackFamilyMissing reports a bind error that means the host has no
// loopback address of that family (IPv6 removed or disabled). The syscall
// package's EADDRNOTAVAIL and EAFNOSUPPORT are invented values on Windows,
// which Winsock never returns, so the Winsock codes are compared. Every
// other error, in use (WSAEADDRINUSE) or access denied (WSAEACCES, another
// program holding the port exclusively) above all, is not.
func loopbackFamilyMissing(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL) || errors.Is(err, windows.WSAEAFNOSUPPORT) || errors.Is(err, windows.WSAEPROTONOSUPPORT)
}
