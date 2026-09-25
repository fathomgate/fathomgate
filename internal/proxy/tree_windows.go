// SPDX-License-Identifier: Apache-2.0

//go:build windows

package proxy

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// procTree is the upstream's Job Object (ADR 0021): unnamed, not inheritable,
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, and no breakaway limit, so no
// descendant can leave it and the kernel ends the tree when the last handle
// closes, including when fathomgate itself dies. One job per process, so the
// ADR 0018 restart ends the first process's tree and nothing else.
type procTree struct {
	mu   sync.Mutex
	job  windows.Handle // 0 once closed
	once sync.Once
}

// prepareTree starts the upstream suspended, so that it runs nothing, and
// starts nothing outside the job, before attachTree has assigned it.
func prepareTree(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
}

// attachTree puts a started cmd in a new job and, if prepareTree started it
// suspended, resumes it. On error the job is closed and the process has not
// been resumed; the caller must kill it.
func attachTree(cmd *exec.Cmd) (_ *procTree, err error) {
	if cmd.Process == nil {
		return &procTree{}, nil
	}
	suspended := cmd.SysProcAttr != nil && cmd.SysProcAttr.CreationFlags&windows.CREATE_SUSPENDED != 0
	// cmd.Process holds a handle to the process until it is reaped, so its
	// PID cannot have been reused.
	pid := uint32(cmd.Process.Pid) //nolint:gosec // G115: a Windows PID is a DWORD; os stores it as int

	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	defer func() {
		if err != nil {
			_ = windows.CloseHandle(job)
		}
	}()
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	//nolint:gosec // G103: SetInformationJobObject takes the struct by pointer; &info lives across the call
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return nil, fmt.Errorf("set job object limits: %w", err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return nil, fmt.Errorf("open upstream process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		return nil, fmt.Errorf("assign upstream process to its job object: %w", err)
	}
	if suspended {
		if err := resumeProcess(pid); err != nil {
			return nil, fmt.Errorf("resume upstream process: %w", err)
		}
	}
	return &procTree{job: job}, nil
}

// resumeProcess resumes the threads of process pid. syscall.StartProcess
// closes the main thread's handle and exposes no thread ID, so the thread is
// found in a Toolhelp32 snapshot. A process just created suspended has
// exactly one thread; finding none is an error.
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, te.ThreadID)
		if err != nil {
			return fmt.Errorf("open thread %d: %w", te.ThreadID, err)
		}
		_, err = windows.ResumeThread(th)
		_ = windows.CloseHandle(th)
		if err != nil {
			return fmt.Errorf("resume thread %d: %w", te.ThreadID, err)
		}
		resumed++
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return fmt.Errorf("thread snapshot: %w", err)
	}
	if resumed == 0 {
		return fmt.Errorf("no thread of process %d in the snapshot", pid)
	}
	return nil
}

// kill terminates every process in the job and closes the job handle.
func (t *procTree) kill() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job == 0 {
		return
	}
	_ = windows.TerminateJobObject(t.job, 1)
	_ = windows.CloseHandle(t.job)
	t.job = 0
}

// terminate is kill: go-sdk cannot send SIGTERM on Windows and kills the
// leader at this point instead.
func (t *procTree) terminate() { t.kill() }

// sweep is kill, once the leader has been reaped. Windows has no SIGTERM to
// give the rest of the tree a grace period with.
func (t *procTree) sweep(time.Duration) {
	if t == nil {
		return
	}
	t.once.Do(t.kill)
}
