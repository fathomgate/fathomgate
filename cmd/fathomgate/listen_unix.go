// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"errors"
	"syscall"
)

// loopbackFamilyMissing reports a bind error that means the host has no
// loopback address of that family: IPv6 disabled on lo (EADDRNOTAVAIL) or
// in the kernel (EAFNOSUPPORT, EPROTONOSUPPORT). Every other error, in use
// above all, is not.
func loopbackFamilyMissing(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// bindControl is nil on Unix: the listener keeps net.Listen's socket
// options (SO_REUSEADDR, which lets fathomgate rebind a port whose old
// connections are in TIME_WAIT; never SO_REUSEPORT). Unix has no
// SO_EXCLUSIVEADDRUSE, and needs none (M1-27):
//
//   - SO_REUSEADDR on Unix does not take over a port. No socket can bind an
//     address and port that a listening socket holds, whatever its options,
//     unless both set SO_REUSEPORT (and, on Linux, belong to the same user);
//     fathomgate never sets SO_REUSEPORT.
//   - Linux also refuses a wildcard bind (0.0.0.0:P, [::]:P) that overlaps a
//     listening socket's address, SO_REUSEADDR or not
//     (TestBindLoopbackRefusesWildcardLinux).
//   - macOS and the BSDs let a socket that sets SO_REUSEADDR bind the
//     wildcard on a port where a specific address listens, but not across
//     users: a non-root user's bind that overlaps a socket of another user
//     fails with EADDRINUSE (in_pcbbind). Root is outside the threat model.
//
// So on Unix another local user can take the port only while fathomgate is
// not bound to it (docs/security/threat-model.md, the port squatting row).
var bindControl func(network, address string, c syscall.RawConn) error
