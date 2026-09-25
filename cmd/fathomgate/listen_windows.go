// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
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
// (ADR 0029 decision 4, M1-27). Microsoft documents that with it no other
// socket can bind the same address and port, whatever its options
// ("Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE"). Without it, whether a
// socket that sets SO_REUSEADDR can take the address over is left to
// Winsock's default checks; on Windows 11 build 26200, same user, that
// takeover already failed with WSAEACCES. So this is defence in depth, and
// TestBindLoopbackExclusiveWindows checks the option is set. It covers only
// the exact address bound; holdWildcards covers the wildcards. A failure to
// set it fails the bind.
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

// wildcard is one wildcard address holdWildcards binds.
type wildcard struct {
	host   string // 0.0.0.0 or [::], for errors
	kind   string // "", " (IPv6 only)" or " (dual-stack)", for errors
	family int32
	v6only int // IPV6_V6ONLY for AF_INET6; unused for AF_INET
}

// wildcards are the three kinds of wildcard bind of port P that would
// receive connections to 127.0.0.1:P or [::1]:P once fathomgate stops.
// Each needs its own socket: on Windows 11 build 26200 a dual-stack [::]:P
// and 0.0.0.0:P, for one, can both be bound on the same port.
var wildcards = []wildcard{
	{"0.0.0.0", "", windows.AF_INET, 0},
	{"[::]", " (IPv6 only)", windows.AF_INET6, 1},
	{"[::]", " (dual-stack)", windows.AF_INET6, 0},
}

// holdWildcards binds port on each of the wildcards, after bindLoopback has
// bound the loopback addresses, and holds the sockets until the returned
// Closer is closed (M1-27). The sockets never listen: they accept nothing,
// the agents' connections still reach the loopback listeners (the more
// specific bind), and nothing listens off the host. While they are held no
// other socket, with or without SO_REUSEADDR, can bind port P on a wildcard
// or loopback address (WSAEADDRINUSE, or WSAEACCES with SO_REUSEADDR;
// measured with a same-user socket), so a squatter cannot bind the
// wildcard while fathomgate runs and wait for it to stop. If another
// socket already holds one of them, holdWildcards fails, naming it, and
// fathomgate refuses to start, as on Unix. They are bound without
// SO_EXCLUSIVEADDRUSE, because with it a wildcard bind after fathomgate's
// own loopback bind fails. A wildcard of a family the host lacks is
// skipped. The handles are not inheritable, so the upstream never holds
// the port.
func holdWildcards(port uint16) (io.Closer, error) {
	var held heldSockets
	for _, w := range wildcards {
		s, err := bindWildcard(w, port)
		if err == nil {
			held = append(held, s)
			continue
		}
		if loopbackFamilyMissing(err) {
			continue
		}
		_ = held.Close()
		return nil, fmt.Errorf("%s:%d%s, a wildcard address on the same port, cannot be held (%w)", w.host, port, w.kind, err)
	}
	return held, nil
}

// bindWildcard binds a TCP socket of w's family to the wildcard address on
// port, without listening.
func bindWildcard(w wildcard, port uint16) (windows.Handle, error) {
	s, err := windows.WSASocket(w.family, windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return windows.InvalidHandle, os.NewSyscallError("socket", err)
	}
	var sa windows.Sockaddr = &windows.SockaddrInet4{Port: int(port)}
	if w.family == windows.AF_INET6 {
		if err := windows.SetsockoptInt(s, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, w.v6only); err != nil {
			_ = windows.Closesocket(s)
			return windows.InvalidHandle, os.NewSyscallError("setsockopt IPV6_V6ONLY", err)
		}
		sa = &windows.SockaddrInet6{Port: int(port)}
	}
	if err := windows.Bind(s, sa); err != nil {
		_ = windows.Closesocket(s)
		return windows.InvalidHandle, os.NewSyscallError("bind", err)
	}
	return s, nil
}

// heldSockets are the wildcard sockets holdWildcards holds.
type heldSockets []windows.Handle

// Close closes every socket.
func (h heldSockets) Close() error {
	var errs []error
	for _, s := range h {
		if err := windows.Closesocket(s); err != nil {
			errs = append(errs, os.NewSyscallError("closesocket", err))
		}
	}
	return errors.Join(errs...)
}
