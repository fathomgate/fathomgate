// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package main

// loopbackFamilyMissing reports no error as a missing loopback family on
// platforms that are neither Unix nor Windows, so failing to bind the
// other family's loopback always refuses to start.
func loopbackFamilyMissing(error) bool { return false }
