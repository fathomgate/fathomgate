// SPDX-License-Identifier: Apache-2.0

//go:build unix

package proxy

import (
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// sweepPoll is how often sweep checks whether the group has emptied.
const sweepPoll = 20 * time.Millisecond

// procTree is the upstream's process group (ADR 0021). The child calls
// setpgid between fork and exec, so it is in its group before its first
// instruction and everything it starts inherits the group.
type procTree struct {
	pgid int // the group ID, which is the leader's PID; 0 for no group of its own

	mu    sync.Mutex
	swept bool // sweep has run: the group ID may be reused, never signal it again
	once  sync.Once
}

// prepareTree puts the upstream in a new process group whose ID is its PID.
func prepareTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// attachTree records the group of a started cmd. A cmd that prepareTree did
// not prepare shares fathomgate's group and gets no tree of its own: only
// its leader is ever signalled. It never fails on Unix.
func attachTree(cmd *exec.Cmd) (*procTree, error) {
	a := cmd.SysProcAttr
	if cmd.Process == nil || a == nil || !a.Setpgid || a.Pgid != 0 {
		return &procTree{}, nil
	}
	return &procTree{pgid: cmd.Process.Pid}, nil
}

// signal sends sig to every process in the group (sig 0 only checks that
// one exists). It reports syscall.ESRCH when there is no group or it has
// been swept.
func (t *procTree) signal(sig syscall.Signal) error {
	if t == nil {
		return syscall.ESRCH
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pgid <= 0 || t.swept {
		return syscall.ESRCH
	}
	return syscall.Kill(-t.pgid, sig)
}

// kill sends SIGKILL to the group.
func (t *procTree) kill() { _ = t.signal(syscall.SIGKILL) }

// terminate sends SIGTERM to the group.
func (t *procTree) terminate() { _ = t.signal(syscall.SIGTERM) }

// sweep ends what is left of the group once the leader has been reaped: a
// launcher that exited on stdin EOF while its child did not. SIGTERM, up to
// grace for the group to empty, then SIGKILL. It runs once; later calls
// wait for the first to finish and return. A process group ID is not reused
// while any member lives, so the signals reach only the upstream's tree
// while there is anything to sweep (ADR 0021, Negative).
func (t *procTree) sweep(grace time.Duration) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		defer func() {
			t.mu.Lock()
			t.swept = true
			t.mu.Unlock()
		}()
		if t.signal(syscall.SIGTERM) != nil {
			return // empty (ESRCH), or nothing fathomgate may signal (EPERM)
		}
		deadline := time.Now().Add(grace)
		for time.Now().Before(deadline) {
			time.Sleep(sweepPoll)
			if t.signal(0) != nil {
				return
			}
		}
		t.kill()
	})
}
