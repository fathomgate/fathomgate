// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix || windows

package proxy

import (
	"os/signal"
	"syscall"
)

// ignoreSIGTERM makes a fake upstream ignore SIGTERM (the launcher fixture
// and its lingering child, ADR 0021). On Windows nothing sends it one.
func ignoreSIGTERM() { signal.Ignore(syscall.SIGTERM) }
