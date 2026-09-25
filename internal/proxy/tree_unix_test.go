// SPDX-License-Identifier: Apache-2.0

//go:build unix

package proxy

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// procWatch follows one process by PID. A reparented grandchild is reaped
// by init or launchd, so kill(pid, 0) reaches ESRCH once it is gone.
type procWatch struct{ pid int }

// watchProcess starts watching pid, which must be running now. If the test
// ends with it still running, it is killed.
func watchProcess(t *testing.T, pid int) procWatch {
	t.Helper()
	w := procWatch{pid}
	if !w.alive() {
		t.Fatalf("process %d is not running before the kill", pid)
	}
	t.Cleanup(func() {
		if w.alive() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return w
}

func (w procWatch) alive() bool {
	return !errors.Is(syscall.Kill(w.pid, 0), syscall.ESRCH)
}

// waitGone fails the test unless the process is gone within d.
func (w procWatch) waitGone(t *testing.T, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for w.alive() {
		if time.Now().After(deadline) {
			t.Fatalf("%s (pid %d) is still running %s later", what, w.pid, d)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertPrepared(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if a := cmd.SysProcAttr; a == nil || !a.Setpgid || a.Pgid != 0 {
		t.Fatalf("SysProcAttr %+v: want Setpgid with Pgid 0", a)
	}
}

// TestTreeUnixGrandchildInGroup: the upstream leads a process group of its
// own, not fathomgate's, and the launcher's child is in it.
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
