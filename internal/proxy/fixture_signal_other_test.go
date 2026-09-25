// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package proxy

// ignoreSIGTERM is a no-op where there is no SIGTERM to ignore.
func ignoreSIGTERM() {}
