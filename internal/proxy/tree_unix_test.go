// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package proxy

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// startsSuspended reports whether prepareTree starts the upstream suspended
// until attachTree (Windows only).
const startsSuspended = false

// procWatch follows one process. On Linux os.FindProcess holds a pidfd, so
// a signal can never reach another process that reused the PID; elsewhere
// it is the PID, and gone, set once the process was seen to be gone, keeps
// the cleanup from signalling a reused PID. A reparented grandchild is
// reaped by init or launchd, so it does become gone (ESRCH).
type procWatch struct {
	pid  int
	proc *os.Process
	gone bool
}

// watchProcess starts watching pid, which must be running now. If the test
// ends with it still running, and never seen gone, it is killed.
func watchProcess(t *testing.T, pid int) *procWatch {
	t.Helper()
	proc, err := os.FindProcess(pid)
	if err != nil {
		t.Fatalf("find process %d before the kill: %v", pid, err)
	}
	w := &procWatch{pid: pid, proc: proc}
	if !w.alive() {
		t.Fatalf("process %d is not running before the kill", pid)
	}
	t.Cleanup(func() {
		if !w.gone && w.alive() {
			_ = w.proc.Kill()
		}
		_ = w.proc.Release()
	})
	return w
}

func (w *procWatch) alive() bool {
	err := w.proc.Signal(syscall.Signal(0))
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		w.gone = true
	}
	return !w.gone
}

// waitGone fails the test unless the process is gone within d.
func (w *procWatch) waitGone(t *testing.T, d time.Duration, what string) {
	t.Helper()
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for w.alive() {
		select {
		case <-tick.C:
		case <-deadline.C:
			if w.alive() {
				t.Fatalf("%s (pid %d) is still running %s later", what, w.pid, d)
			}
			return
		}
	}
}

func assertPrepared(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if a := cmd.SysProcAttr; a == nil || !a.Setpgid || a.Pgid != 0 {
		t.Fatalf("SysProcAttr %+v: want Setpgid with Pgid 0", a)
	}
}

// TestProcTreeSweepAfterKill (L3 in the security review of PR #111): a
// group already sent SIGKILL is swept without the grace, so zombies that no
// init reaps (fathomgate as PID 1) cannot hold the sweep for 2 seconds.
func TestProcTreeSweepAfterKill(t *testing.T) {
	cmd := exec.Command(testExecutable(t), "-test.run=^$")
	cmd.Env = append(os.Environ(), fakeUpstreamEnv+"=silent", childRaceEnv)
	prepareTree(cmd)
	if _, err := cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tree, err := attachTree(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	tree.kill()
	// Not reaped yet: the leader is a zombie in its group, which is what
	// PID 1 without an init leaves behind.
	start := time.Now()
	tree.sweep(3 * time.Second) // without the fix it waits all of this
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("sweep after SIGKILL took %s", elapsed)
	}
	_ = cmd.Wait()
}
