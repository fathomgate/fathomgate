// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package main

import "syscall"

// loopbackFamilyMissing reports no error as a missing loopback family on
// platforms that are neither Unix nor Windows, so failing to bind the
// other family's loopback always refuses to start.
func loopbackFamilyMissing(error) bool { return false }

// bindControl is nil: listenTCP is net.Listen on platforms that are neither
// Unix nor Windows.
var bindControl func(network, address string, c syscall.RawConn) error

// holdWildcards is nil: bindLoopback holds no wildcard socket on platforms
// that are neither Unix nor Windows.
var holdWildcards holdFunc
