// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package proxy

import (
	"syscall"
	"testing"
)

// TestTreeUnixGrandchildInGroup: the upstream leads a process group of its
// own, not fathomgate's, and the launcher's child is in it. (syscall has
// Getpgid and Getpgrp only on these systems.)
func TestTreeUnixGrandchildInGroup(t *testing.T) {
	t.Parallel()
	p, b, gc := startBehindLauncher(t, "ignore")
	t.Cleanup(func() { _ = p.Close() })
	leader := b.get()[0].Command.Process.Pid
	if got := p.upstreams[testServer].tt.tree.pgid; got != leader {
		t.Errorf("tree pgid %d, want the upstream's PID %d", got, leader)
	}
	if pg, err := syscall.Getpgid(leader); err != nil || pg != leader {
		t.Errorf("upstream's group: %d, %v; want %d", pg, err, leader)
	}
	if pg, err := syscall.Getpgid(gc.pid); err != nil || pg != leader {
		t.Errorf("launcher's child's group: %d, %v; want %d", pg, err, leader)
	}
	if syscall.Getpgrp() == leader {
		t.Error("fathomgate is in the upstream's group")
	}
	closeProxy(t, p)
	gc.waitGone(t, goneWithin, "the launcher's child after Close")
}
