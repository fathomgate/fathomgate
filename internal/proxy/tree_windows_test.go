// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build windows

package proxy

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startsSuspended reports whether prepareTree starts the upstream suspended
// until attachTree.
const startsSuspended = true

// procWatch holds a handle to one process, opened while it runs, so the
// process can be waited on without a PID that could be reused.
type procWatch struct {
	pid int
	h   windows.Handle
}

// watchProcess opens pid, which must be running now. If the test ends with
// it still running, it is terminated.
func watchProcess(t *testing.T, pid int) *procWatch {
	t.Helper()
	const access = windows.SYNCHRONIZE | windows.PROCESS_TERMINATE | windows.PROCESS_QUERY_LIMITED_INFORMATION //nolint:misspell // Windows API name
	h, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		t.Fatalf("open process %d before the kill: %v", pid, err)
	}
	w := &procWatch{pid: pid, h: h}
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

func (w *procWatch) alive() bool {
	ev, err := windows.WaitForSingleObject(w.h, 0)
	return err == nil && ev == uint32(windows.WAIT_TIMEOUT)
}

// waitGone fails the test unless the process has ended within d.
func (w *procWatch) waitGone(t *testing.T, d time.Duration, what string) {
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

// IsProcessInJob and SuspendThread are not in golang.org/x/sys/windows
// v0.48.0.
var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procIsProcessInJob = kernel32.NewProc("IsProcessInJob")
	procSuspendThread  = kernel32.NewProc("SuspendThread")
)

func isProcessInJob(t *testing.T, h, job windows.Handle) bool {
	t.Helper()
	var in int32
	r, _, err := procIsProcessInJob.Call(uintptr(h), uintptr(job), uintptr(unsafe.Pointer(&in)))
	if r == 0 {
		t.Fatalf("IsProcessInJob: %v", err)
	}
	return in != 0
}

// suspendCount returns the highest suspend count among pid's threads,
// read with SuspendThread and undone with ResumeThread at once.
func suspendCount(t *testing.T, pid int) uint32 {
	t.Helper()
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	threads := 0
	var most uint32
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != uint32(pid) {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			t.Fatal(err)
		}
		prev, _, callErr := procSuspendThread.Call(uintptr(th))
		if uint32(prev) == 0xFFFFFFFF {
			_ = windows.CloseHandle(th)
			t.Fatalf("SuspendThread: %v", callErr)
		}
		_, _ = windows.ResumeThread(th)
		_ = windows.CloseHandle(th)
		threads++
		most = max(most, uint32(prev))
	}
	if threads == 0 {
		t.Fatalf("no thread of process %d in the snapshot", pid)
	}
	return most
}

// TestTreeWindowsStartsSuspended (S2 in the Go review of PR #111): a
// process Command.Transport prepared is suspended after Start, runs nothing
// until attachTree, and runs once attachTree has resumed it. With
// CREATE_SUSPENDED removed from prepareTree this test fails.
func TestTreeWindowsStartsSuspended(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	cmd := Command{
		Path: testExecutable(t),
		Args: []string{"-test.run=^$"},
		Env:  []string{fakeUpstreamEnv + "=marker", markerEnv + "=" + marker, childRaceEnv},
	}.Transport().Command
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	watch := watchProcess(t, cmd.Process.Pid)
	if n := suspendCount(t, cmd.Process.Pid); n < 1 {
		t.Errorf("main thread suspend count %d after Start, want at least 1", n)
	}
	// Give a running process ample time to write its marker.
	<-time.After(500 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the process ran before attachTree (marker: %v)", err)
	}
	tree, err := attachTree(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tree.kill)
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("the process did not run after attachTree resumed it")
		}
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Errorf("the resumed process: %v", err)
	}
	watch.waitGone(t, goneWithin, "the resumed process")
}

// TestResumeProcessExited (L2 in the security review of PR #111):
// resumeProcess fails for a process that has no thread left. A handle is
// held across the exit so the PID cannot be reused by another process.
func TestResumeProcessExited(t *testing.T) {
	cmd := exec.Command(testExecutable(t), "-test.run=^$")
	cmd.Env = append(os.Environ(), fakeUpstreamEnv+"=die", childRaceEnv)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid)) //nolint:misspell // Windows API name
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	_ = cmd.Wait()
	if err := resumeProcess(uint32(pid)); err == nil {
		t.Fatal("resumeProcess succeeded for a process that has exited")
	}
}

// TestTreeWindowsGrandchildInJob: the launcher starts its child at its
// first instruction (runLauncher is the first thing TestMain does), and
// the child is still in the upstream's job. The upstream itself is in the
// job, and the test process is not. That the upstream ran nothing before it
// was assigned is TestTreeWindowsStartsSuspended's to prove.
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
