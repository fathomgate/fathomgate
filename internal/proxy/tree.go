// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"sync/atomic"
	"time"
)

// The upstream's process tree (ADR 0021). A stdio upstream is started in a
// process group of its own on Unix and in a Job Object of its own on
// Windows, so that everything it starts (the server behind `uvx`, `npx`,
// `uv run` or a shell script) is stopped with it. The platform files define
// procTree and these functions and methods:
//
//   - prepareTree(cmd) sets cmd.SysProcAttr before the start: Setpgid on
//     Unix, CREATE_SUSPENDED on Windows. Command.Transport calls it.
//   - attachTree(cmd, logger) runs after the start and before anything is
//     written to the upstream (trackedTransport.Connect); logger receives
//     the one warn line a Unix tree logs when it may not signal its group
//     (EPERM: a setuid launcher). On Unix it records the group;
//     on Windows it creates the job, assigns the process to it and resumes
//     it. An error means the process must not run: the caller kills it and
//     the attempt fails.
//   - kill ends the whole tree at once: SIGKILL to the group, or
//     TerminateJobObject and closing the job handle.
//   - terminate is the tree's half of go-sdk's first shutdown signal: SIGTERM
//     to the group on Unix; on Windows, where go-sdk kills the leader at that
//     point instead, it is kill.
//   - sweep runs once, after the leader has been reaped: SIGTERM to the
//     group, up to grace for it to empty, then SIGKILL (Unix); if the group
//     has already been sent SIGKILL, only SIGKILL again, with no grace;
//     kill (Windows).
//     After it the tree is never signalled again, so a reused process group
//     ID cannot be hit by a later kill.
//
// Every method is safe on a nil *procTree (a transport that owns no process)
// and from any goroutine.

// treeSignalLag is how long after go-sdk's own shutdown signal to the leader
// the group gets the same signal (mirrorShutdown). go-sdk's pipeRWC.Close
// signals the leader when terminateDuration has passed since it closed stdin,
// and gives up if the leader has already been reaped by then. Signalling the
// group, leader included, at the same instant could get the leader reaped
// just before go-sdk's own signal. The lag keeps go-sdk's signal first, but
// only as a best effort: two independent timers, with no ordering guarantee,
// so a go-sdk goroutine delayed by more than the lag can still lose. Then
// go-sdk's close returns "os: process already finished" instead of the
// process's exit status, without waiting for it, and the last lines of the
// upstream's stderr that exec had not yet copied are lost. The tree is still
// ended.
const treeSignalLag = 250 * time.Millisecond

// attachFault, when a test sets it, makes attachTree fail with its error
// after the process has been put in its tree and before it is resumed, so
// the fail-closed path (ADR 0021) can be tested. Nothing outside tests sets
// it.
var attachFault atomic.Pointer[error]

// injectedFault returns the error a test has set in attachFault, or nil.
func injectedFault() error {
	if e := attachFault.Load(); e != nil {
		return *e
	}
	return nil
}

// mirrorShutdown schedules the tree's share of go-sdk's shutdown sequence,
// counted from now, which is when the connection's Close starts and go-sdk
// closes the upstream's stdin: terminate at terminateDuration, kill at twice
// that, each treeSignalLag after go-sdk signals the leader. The returned
// function cancels whatever has not fired; call it once Close has returned.
func (t *procTree) mirrorShutdown() (stop func()) {
	if t == nil {
		return func() {}
	}
	term := time.AfterFunc(terminateDuration+treeSignalLag, t.terminate)
	kill := time.AfterFunc(2*terminateDuration+treeSignalLag, t.kill)
	return func() {
		term.Stop()
		kill.Stop()
	}
}
