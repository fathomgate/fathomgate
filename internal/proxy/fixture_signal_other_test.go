// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !unix && !windows

package proxy

// ignoreSIGTERM is a no-op where there is no SIGTERM to ignore.
func ignoreSIGTERM() {}
