// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package main

// errFamilyMissing is nil: no bind error counts as a missing loopback
// family on this platform (listen_other.go).
var errFamilyMissing error

// addrTaken reports no bind error as another socket holding the address,
// so on this platform any first-bind failure fails the test at once
// (squatAttempts).
func addrTaken(error) bool { return false }
