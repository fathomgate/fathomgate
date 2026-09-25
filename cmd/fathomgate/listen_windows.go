// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"

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

// soExclusiveAddrUse is Winsock's SO_EXCLUSIVEADDRUSE, defined in winsock2.h
// as ((int)(~SO_REUSEADDR)). golang.org/x/sys/windows v0.48.0 does not
// define it.
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

// bindControl sets SO_EXCLUSIVEADDRUSE on a listener socket before bind
// (ADR 0029 decision 4, M1-27). With it no other socket, whatever its
// options or its owner, can bind the same address and port while
// fathomgate holds it. Without it, whether a socket that sets SO_REUSEADDR
// can take over the port is left to Winsock's default "enhanced socket
// security" checks, which depend on the Windows version and on who owns
// each socket (on Windows 11 build 26200, same user, the takeover already
// fails with WSAEACCES; the option makes that hold whatever the version or
// owner, and TestBindLoopbackExclusiveWindows checks it is set). The option
// holds only for the exact address bound (127.0.0.1:P or [::1]:P): a
// wildcard bind of the same port
// (0.0.0.0:P or [::]:P) by another socket still succeeds, and that socket
// receives the agents' loopback connections once fathomgate stops
// (docs/security/threat-model.md, the port squatting row). A failure to set
// the option fails the bind.
func bindControl(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soExclusiveAddrUse, 1)
	}); err != nil {
		return err
	}
	if serr != nil {
		return os.NewSyscallError("setsockopt SO_EXCLUSIVEADDRUSE", serr)
	}
	return nil
}
