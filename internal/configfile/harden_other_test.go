// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !windows

package configfile

import "testing"

// ownerOnlyDir is a no-op: t.TempDir is 0700 and write creates 0600.
func ownerOnlyDir(_ *testing.T, dir string) string { return dir }
