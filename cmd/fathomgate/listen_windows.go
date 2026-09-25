// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"syscall"
)

// Winsock errors for a family the host does not have. The syscall
// package's EADDRNOTAVAIL and EAFNOSUPPORT are invented values on Windows,
// which Winsock never returns.
const (
	wsaeProtoNoSupport syscall.Errno = 10043
	wsaeAFNoSupport    syscall.Errno = 10047
	wsaeAddrNotAvail   syscall.Errno = 10049
)

// loopbackFamilyMissing reports a bind error that means the host has no
// loopback address of that family (IPv6 removed or disabled). Every other
// error, in use (WSAEADDRINUSE) or access denied (WSAEACCES, another
// program holding the port exclusively) above all, is not.
func loopbackFamilyMissing(err error) bool {
	return errors.Is(err, wsaeAddrNotAvail) || errors.Is(err, wsaeAFNoSupport) || errors.Is(err, wsaeProtoNoSupport)
}
