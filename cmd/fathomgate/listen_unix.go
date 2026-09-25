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
