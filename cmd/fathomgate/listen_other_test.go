// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package main

// errFamilyMissing is nil: no bind error counts as a missing loopback
// family on this platform (listen_other.go).
var errFamilyMissing error
