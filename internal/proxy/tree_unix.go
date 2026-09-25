// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package proxy

import (
	"errors"
	"log/slog"
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
	pgid   int          // the group ID, which is the leader's PID; 0 for no group of its own
	logger *slog.Logger // for the one EPERM warning; never nil in a tree with a group

	mu     sync.Mutex
	killed bool // SIGKILL has been sent to the group
	swept  bool // sweep has run: the group ID may be reused, never signal it again
	warned bool // the EPERM warning has been logged
	once   sync.Once
}

// prepareTree puts the upstream in a new process group whose ID is its PID.
func prepareTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// attachTree records the group of a started cmd. A cmd that prepareTree did
// not prepare shares fathomgate's group and gets no tree of its own: only
// its leader is ever signalled. On Unix it fails only when a test injects a
// fault (attachFault).
func attachTree(cmd *exec.Cmd, logger *slog.Logger) (*procTree, error) {
	if err := injectedFault(); err != nil {
		return nil, err
	}
	a := cmd.SysProcAttr
	if cmd.Process == nil || a == nil || !a.Setpgid || a.Pgid != 0 {
		return &procTree{}, nil
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &procTree{pgid: cmd.Process.Pid, logger: logger}, nil
}

// signal sends sig to every process in the group (sig 0 only checks that
// one exists). It reports syscall.ESRCH when there is no group or it has
// been swept. The first EPERM is logged at Warn: some member runs as
// another user (a setuid launcher such as sudo), so fathomgate cannot stop
// it, and it may outlive the upstream (ADR 0021 residual).
func (t *procTree) signal(sig syscall.Signal) error {
	if t == nil {
		return syscall.ESRCH
	}
	t.mu.Lock()
	if t.pgid <= 0 || t.swept {
		t.mu.Unlock()
		return syscall.ESRCH
	}
	err := syscall.Kill(-t.pgid, sig)
	if sig == syscall.SIGKILL && err == nil {
		t.killed = true
	}
	warn := errors.Is(err, syscall.EPERM) && !t.warned
	if warn {
		t.warned = true
	}
	t.mu.Unlock()
	if warn {
		t.logger.Warn("the upstream's process group has a member fathomgate may not signal (EPERM), such as a setuid launcher; it may outlive the upstream",
			"pgid", t.pgid)
	}
	return err
}

// kill sends SIGKILL to the group.
func (t *procTree) kill() { _ = t.signal(syscall.SIGKILL) }

// terminate sends SIGTERM to the group.
func (t *procTree) terminate() { _ = t.signal(syscall.SIGTERM) }

// sweep ends what is left of the group once the leader has been reaped: a
// launcher that exited on stdin EOF while its child did not. SIGTERM, up to
// grace for the group to empty, then SIGKILL. If the group has already been
// sent SIGKILL (the restart, a failed start, the shutdown's second signal),
// it is sent SIGKILL once more and there is no grace: every member is dying
// already, and when fathomgate is PID 1 with no init to reap them (the
// distroless image without `docker run --init`), their zombies would keep
// the group non-empty for the whole grace. It runs once; later calls wait
// for the first to finish and return. A process group ID is not reused
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
		t.mu.Lock()
		killed := t.killed
		t.mu.Unlock()
		if killed {
			t.kill()
			return
		}
		if t.signal(syscall.SIGTERM) != nil {
			return // empty (ESRCH), or nothing fathomgate may signal (EPERM)
		}
		deadline := time.NewTimer(grace)
		defer deadline.Stop()
		tick := time.NewTicker(sweepPoll)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if t.signal(0) != nil {
					return
				}
			case <-deadline.C:
				t.kill()
				return
			}
		}
	})
}
