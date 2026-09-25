// SPDX-License-Identifier: Apache-2.0

//go:build windows

package proxy

import (
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procWatch holds a handle to one process, opened while it runs, so the
// process can be waited on without a PID that could be reused.
type procWatch struct {
	pid int
	h   windows.Handle
}

// watchProcess opens pid, which must be running now. If the test ends with
// it still running, it is terminated.
func watchProcess(t *testing.T, pid int) procWatch {
	t.Helper()
	const access = windows.SYNCHRONIZE | windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION //nolint:misspell // Windows API name
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		t.Fatalf("open process %d before the kill: %v", pid, err)
	}
	w := procWatch{pid: pid, h: h}
	t.Cleanup(func() {
		if w.alive() {
			_ = windows.TerminateProcess(h, 1)
		}
		_ = windows.CloseHandle(h)
	})
	if !w.alive() {
		t.Fatalf("process %d is not running before the kill", pid)
	}
	return w
}

func (w procWatch) alive() bool {
	ev, err := windows.WaitForSingleObject(w.h, 0)
	return err == nil && ev == uint32(windows.WAIT_TIMEOUT)
}

// waitGone fails the test unless the process has ended within d.
func (w procWatch) waitGone(t *testing.T, d time.Duration, what string) {
	t.Helper()
	ev, err := windows.WaitForSingleObject(w.h, uint32(d.Milliseconds()))
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("%s (pid %d) is still running %s later (%#x, %v)", what, w.pid, d, ev, err)
	}
}

func assertPrepared(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if a := cmd.SysProcAttr; a == nil || a.CreationFlags&windows.CREATE_SUSPENDED == 0 {
		t.Fatalf("SysProcAttr %+v: want CREATE_SUSPENDED", a)
	}
}

// IsProcessInJob is not in golang.org/x/sys/windows v0.48.0.
var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func isProcessInJob(t *testing.T, h, job windows.Handle) bool {
	t.Helper()
	var in int32
	r, _, err := procIsProcessInJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&in)))
	if r == 0 {
		t.Fatalf("IsProcessInJob: %v", err)
	}
	return in != 0
}

// TestTreeWindowsGrandchildInJob: the launcher starts its child at its
// first instruction (runLauncher is the first thing TestMain does), and
// the child is still in the upstream's job: the process ran nothing before
// it was assigned, so the race between CreateProcess and
// AssignProcessToJobObject is closed. The upstream itself is in the job,
// and the test process is not.
func TestTreeWindowsGrandchildInJob(t *testing.T) {
	t.Parallel()
	p, b, gc := startBehindLauncher(t, "ignore")
	t.Cleanup(func() { _ = p.Close() })
	tree := p.upstreams[testServer].tt.tree
	tree.mu.Lock()
	job := tree.job
	tree.mu.Unlock()
	if job == 0 {
		t.Fatal("the upstream has no job")
	}
	if !isProcessInJob(t, gc.h, job) {
		t.Error("the launcher's child is not in the upstream's job")
	}
	leader := watchProcess(t, b.get()[0].Command.Process.Pid)
	if !isProcessInJob(t, leader.h, job) {
		t.Error("the upstream is not in its job")
	}
	if isProcessInJob(t, windows.CurrentProcess(), job) {
		t.Error("the test process is in the upstream's job")
	}
	closeProxy(t, p)
	gc.waitGone(t, goneWithin, "the launcher's child after Close")
}
