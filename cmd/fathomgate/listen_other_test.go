// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package main

// errFamilyMissing is nil: no bind error counts as a missing loopback
// family on this platform (listen_other.go).
var errFamilyMissing error
