# ADR 0021: Kill the upstream's whole process tree: a process group on Unix, a Job Object on Windows

- Status: accepted
- Date: 2026-09-24
- Amended: 2026-09-25 (T0.46 reviews), facts only; the decision is unchanged. See [Amendments](#amendments).
- Deciders: Josh Scott (maintainer; to accept); proposed by docs-writer for T0.46; owner mcp-protocol-engineer; reviewers security-reviewer, go-reviewer

## Context

Fathomgate stops only the process it started. When `--upstream` is a launcher (`uvx`, `npx`, `uv run`, a shell script, `docker run -i`), that process is the launcher, and the real MCP server is its child: Fathomgate's grandchild. Three paths stop an upstream, and none of them reaches the grandchild.

| Path | What is signalled today | Where |
| --- | --- | --- |
| [ADR 0018](0018-bound-server-discover-then-initialize-only.md) restart, and every failed startup attempt | `Process.Kill` on the direct child | `trackedTransport.killProcess`, `internal/proxy/proxy.go:563-572`, called from `connect` (`proxy.go:342`, `345`, `363`), `connectAttempt` (`proxy.go:401`) and `trackedTransport.kill` (`proxy.go:636-663`); the late kill in `trackedTransport.Connect` (`proxy.go:520-524`) |
| Shutdown (`Proxy.Close`) | go-sdk closes stdin, waits `TerminateDuration` (5 s), sends `SIGTERM` to `cmd.Process`, waits 5 s more, then `cmd.Process.Kill()`; on Windows `SIGTERM` fails, so it kills after the first 5 s | `Proxy.Close`, `proxy.go:945-977`, calling go-sdk v1.8.0 `pipeRWC.Close`, `mcp/cmd.go:69-108` (signal at line 95, kill at line 101) |
| The upstream exits mid-session | Nothing: the exit watcher logs and returns | `proxy.go:306-312` |

The `Command` godoc says so (`internal/proxy/command.go:34-41`), and so does `trackedTransport.kill` (`proxy.go:626-627`). The security review of PR #77 (T0.39) rated it S2, medium: after the restart the real server keeps running beside the second copy, with the same `--upstream-env-pass` credentials in its environment and any device session it opened. T0.34 showed that such a server does not exit once its receive loop dies. Its stdio is closed, so it cannot be driven: this is credential and resource exposure, not a policy bypass. The same grandchild holds the upstream's stderr pipe, so reaping the killed launcher waits out the `exec.Cmd` `WaitDelay` (`waitDelay`, 2 s, `command.go:16-19`), and startup can overrun its 30-second budget by that much ([ADR 0018](0018-bound-server-discover-then-initialize-only.md), second amendment row; profile-schema 8.3). The operator mitigation today is to point `--upstream` at the server itself ([install.md](../install.md#point---upstream-at-the-server-not-at-a-launcher), README); the [threat model](../security/threat-model.md) carries the row as open, and [SECURITY.md](../../SECURITY.md) line 76 as open for M1.

What the code can control: go-sdk's `CommandTransport` takes a caller-built `*exec.Cmd` (`mcp/cmd.go:20-26`) and calls `Command.Start()` itself inside `Connect` (`mcp/cmd.go:39`). Fathomgate builds that `exec.Cmd` in `Command.Transport` (`command.go:81-101`), so it can set `SysProcAttr` before the start. It cannot change what go-sdk signals on `Close`, and it sees the started process only when go-sdk's `Connect` returns into `trackedTransport.Connect` (`proxy.go:506-527`), which runs before go-sdk writes anything to the upstream.

The Windows fix needs `golang.org/x/sys/windows`, because the standard library's `syscall` has no Job Object calls. `golang.org/x/sys` is already a direct dependency, but [ADR 0011](0011-accept-go-sdk-transitive-modules.md)'s module table and CLAUDE.md record one import path for it, `internal/audit` (`internal/audit/key_windows.go:13`, the key-file DACL). Every function this record needs is in the pinned `v0.48.0`: `CreateJobObject`, `SetInformationJobObject`, `AssignProcessToJobObject`, `TerminateJobObject`, `OpenProcess`, `CreateToolhelp32Snapshot`, `Thread32First`, `Thread32Next`, `OpenThread`, `ResumeThread` (`windows/zsyscall_windows.go`) and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (`windows/types_windows.go:2552`).

## Decision

We will start every stdio upstream in a process group of its own on Unix and in a Job Object of its own on Windows, and stop the upstream by stopping the whole group or job, on the restart, on every failed startup attempt, on shutdown and when the upstream exits mid-session.

### Unix (Linux and macOS)

- `Command.Transport` sets `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}` (`Pgid` 0), so the upstream's process group ID is its PID. The child calls `setpgid` between `fork` and `exec` (Go 1.26.8 `src/syscall/exec_linux.go:393-398`; `src/syscall/exec_libc2.go:121-123` on macOS), so the upstream is in its group before it runs its first instruction, and every process it starts inherits the group. There is no window to close on Unix.
- Where `killProcess` calls `proc.Kill()` today, it sends `SIGKILL` to the group (`syscall.Kill(-pgid, syscall.SIGKILL)`) and still kills the leader by its `os.Process`, in case the launcher left the group. This covers the restart, every failed attempt and the startup budget running out; `exitGrace` (2 s, `proxy.go:33-36`) and `graceFor` keep deciding how long a failed attempt waits before that kill.
- On shutdown the group gets the same signals as the leader at the same points: after stdin is closed and `terminateDuration` (5 s, `command.go:21-29`) passes, `SIGTERM` to the group; 5 s later, `SIGKILL` to the group. go-sdk still signals the leader itself; Fathomgate adds the group, keyed off the same `terminateDuration` constant it already pins so that go-sdk cannot move it unnoticed.
- After the leader is reaped, on shutdown and in the exit watcher, Fathomgate sweeps the group once: `SIGTERM`, up to `exitGrace` for the group to empty, then `SIGKILL`. This catches a launcher that exits on stdin EOF while its child does not.
- The standard library's `syscall` has `Setpgid` and `Kill` on both Linux and macOS, so Unix needs no `golang.org/x/sys/unix` import.
- `PR_SET_PDEATHSIG` and cgroups are not used; see Alternatives.

### Windows

- For each upstream process, Fathomgate creates an unnamed, non-inheritable Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and without `JOB_OBJECT_LIMIT_BREAKAWAY_OK` or `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`, so no descendant can leave it. One job per process, not one per `Proxy`, so the restart ends the first process's tree and nothing else.
- The race: between `CreateProcess` and `AssignProcessToJobObject` the launcher runs, and a child it starts in that window is not in the job. We close it by starting the upstream suspended. `Command.Transport` sets `SysProcAttr.CreationFlags |= CREATE_SUSPENDED` (a Windows-only file). In `trackedTransport.Connect`, which runs after go-sdk's `Start` and before go-sdk's first write, Fathomgate opens the process by PID (safe: `os.Process` holds a handle, so the PID cannot be reused), assigns it to the job, and then resumes it.
- Resuming is the awkward part: `syscall.StartProcess` closes the main thread's handle before it returns (Go 1.26.8 `src/syscall/exec_windows.go:446`) and exposes no thread ID. A suspended new process has exactly one thread, so Fathomgate finds it with `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)` and `Thread32First`/`Thread32Next` filtered by owner PID, then `OpenThread(THREAD_SUSPEND_RESUME)` and `ResumeThread`. About 30 lines, all in `x/sys/windows` v0.48.0.
- Fail closed: if creating the job, assigning to it or resuming fails, Fathomgate terminates the process and the attempt fails with that error. An upstream never runs outside its job. Nested jobs are supported since Windows 8, so a Fathomgate that is itself in a job (a CI runner, some terminals) can still assign.
- Stopping: wherever Unix sends `SIGKILL` to the group, Windows calls `TerminateJobObject` and closes the job handle. go-sdk sends no `SIGTERM` on Windows (`Process.Signal` fails there, `mcp/cmd.go:95`), so shutdown keeps today's order (close stdin, 5 s, kill) and the kill ends the job, not only the leader.
- Because of `KILL_ON_JOB_CLOSE`, the kernel ends the tree when the last job handle closes, including when Fathomgate itself crashes or is killed. Unix has no equivalent in this decision (see Negative).

### ADR 0011 and CLAUDE.md

- `internal/proxy` imports `golang.org/x/sys/windows` on Windows only. No module is added, removed or moved, and the version stays `v0.48.0`, so this is a new import path of an existing direct dependency, the same kind of change as the T0.16 row in ADR 0011. When the code lands, ADR 0011 gains a dated amendment row that adds `internal/proxy` → `golang.org/x/sys/windows` (Job Object, Windows only) to the `golang.org/x/sys` "Why" column and points here, and the CLAUDE.md toolchain line names both importers. ADR 0011's decision and guardrails are unchanged; `CGO_ENABLED=0` still holds, since `x/sys/windows` is pure Go.

### What stays the same

- stderr relay: `lineWriter`, the redactor, the 4096-byte cut and `flushStderr` after reaping.
- `WaitDelay` (2 s) stays on the `exec.Cmd` as the backstop for a descendant that escaped the group or job.
- [ADR 0018](0018-bound-server-discover-then-initialize-only.md): the 5-second probe bound, the single restart, `initialize` only on the second attempt, the warn line, and the 30-second `startupTimeout` over spawn, both attempts and `tools/list`.
- go-sdk's shutdown order and `TerminateDuration`; `exitGrace` and the T0.25 exit-status attribution (`endedOnItsOwn`), which read only the leader.
- `Proxy.Upstream{Server, NewTransport}` and every other export in [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md)'s API list. ADR 0012's "If `New` fails after a `Command` process started, the process is killed" becomes true of the whole tree; no amendment row is needed, as the sentence stays correct.

### Tests

| Test | Proves | Where it runs |
| --- | --- | --- |
| Launcher fixture: a new `FATHOMGATE_TEST_FAKE_UPSTREAM` mode in the existing `TestMain` helper (`internal/proxy/stdio_test.go:34-60`). The launcher re-executes the test binary as a child in the existing `silent` or `nodiscover` mode, reports the child's PID on stderr, and ignores stdin EOF and `SIGTERM`. A Go helper, not a shell script, so the same fixture runs on Windows | the fixture | all three |
| The ADR 0018 restart, forced with the existing `discoverExpired` test hook, leaves the first grandchild gone | restart | Linux, macOS, Windows |
| `Proxy.Close` leaves the grandchild gone, with the launcher both ignoring and obeying stdin EOF (the post-reap sweep) | shutdown | Linux, macOS, Windows |
| The startup budget running out while a grandchild holds stderr returns within the budget plus scheduling slack, not the budget plus `WaitDelay` | the 2 s overrun is gone | Linux, macOS, Windows |
| The leader exits mid-session and the exit watcher sweeps its grandchild | exit watcher | Linux, macOS, Windows |
| The fixture's child is created at the launcher's first instruction and is in the job (`IsProcessInJob`) | the Windows race is closed | Windows |

"Gone" is checked against a handle opened before the kill, not a bare PID: on Windows the test opens the grandchild's process handle and waits on it; on Unix it polls `kill(pid, 0)` until `ESRCH`, since a reparented grandchild is reaped by init or launchd. CI today runs `go test` on `ubuntu-latest` (`.github/workflows/ci.yaml:26`) and `windows-latest` (`ci.yaml:184-221`); macOS is covered only by lint's cross-analysis (`ci.yaml:264-267`). The code PR adds a `macos-latest` job that runs at least `go test -race ./internal/proxy/`. A tier 2 case with a real launcher in front of a real server (`uv run` in front of `upa/mcp-netmiko-server` on its own `uv.lock`, which takes the ADR 0018 restart) asserts one server process after the restart; the test-engineer decides whether that extends matrix row 2 or becomes a new row.

### When the code lands

- The [threat model](../security/threat-model.md) row "Orphaned grandchild after the ADR 0018 restart" moves from Open to Mitigated (T0.46), with the residuals below. SECURITY.md line 76 ("Grandchildren survive a kill") is closed in the same PR; it still names `killCommand`, which no longer exists.
- ADR 0018's second amendment row and profile-schema 8.3 drop "except for up to 2 seconds (the `exec.Cmd` `WaitDelay`)" for the restart and startup paths, and 8.3's shutdown and "only the direct child is killed" sentences describe the group and the job. That is a fact change in ADR 0018, not a decision change, so it is a new amendment row there.
- The `Command` godoc (`command.go:34-41`) and the `trackedTransport.kill` godoc (`proxy.go:626-627`) are rewritten.
- [install.md](../install.md#point---upstream-at-the-server-not-at-a-launcher) narrows its warning but keeps the section. The "A stopped launcher can leave the server running" bullet is dropped for `uvx`, `npx`, `uv run` and a shell script once the tier 2 case and a manual check on each OS show their server stays in the group or job; it stays for `docker run -i` (the container is not in Fathomgate's process tree; see Negative) and for any launcher that daemonises. The first bullet, "A slow first start costs you the newer protocol", is unaffected by this record, so "point `--upstream` at the server" stays the advice. The README sentence follows install.md.

## Consequences

### Positive

- The ADR 0018 restart no longer leaves a second live copy of the server holding the operator's `--upstream-env-pass` credentials and device sessions. Same for every failed startup and for shutdown.
- Startup meets its 30-second budget on the restart and kill paths: the grandchild dies with the launcher, its stderr closes, and reaping no longer waits out `WaitDelay`.
- On Windows the tree dies even when Fathomgate crashes, because the kernel closes the job handle.
- On Unix, Ctrl-C in the terminal running `fathomgate serve` now reaches only Fathomgate, which then stops the upstream in order (stdin, `SIGTERM`, `SIGKILL`) instead of the upstream receiving `SIGINT` at the same moment as its proxy.

### Negative

- **Deliberate escape stays possible (residual, out of scope).** On Unix a descendant that calls `setsid()` or `setpgid()` leaves the group; on Windows a descendant can start processes outside the job only through another service (WMI, the Task Scheduler, a daemon), since breakaway is not allowed. The operator chose to run that launcher. `WaitDelay` still bounds the wait on its stderr.
- **`docker run -i` is not covered.** The container's processes are children of the container runtime (containerd-shim), not of the `docker` CLI, so neither a process group nor a job reaches them, whatever the CLI does with its session. Killing the group sends the CLI `SIGTERM` first, which the CLI forwards to the container by default in non-TTY mode (`--sig-proxy`), and closes the container's stdin when the CLI dies; a server that ignores both keeps running. install.md keeps its warning for Docker.
- **A Fathomgate crash on Unix still orphans the tree.** Nothing signals the group when Fathomgate is `SIGKILL`ed. The grandchild's stdin reaches EOF; a server that ignores that keeps running, as today. Running Fathomgate under systemd (whose default `KillMode=control-group` kills the unit's cgroup on stop) covers it; install.md can say so.
- **The post-reap sweep is PID-based.** POSIX does not reuse a process group ID while any member of the group lives, so the sweep is exact while there is anything to sweep. If the group has already emptied, the signal can reach an unrelated process only if the kernel reused that exact PID as a new group leader in between. Accepted, the same residual as any PID-based kill; before the leader is reaped (the restart and failed-attempt paths) it does not arise.
- **An upstream that reads the controlling terminal is stopped.** In its own process group the upstream is a background job, so if Fathomgate runs in an interactive terminal and the upstream opens `/dev/tty` (an `ssh` password or host-key prompt), it gets `SIGTTIN` and stops instead of prompting. MCP hosts start Fathomgate without a terminal, and an upstream prompting on a terminal it shares with its proxy is not a supported path; the upstream's stdin and stderr are pipes and are unaffected.
- **The Windows start is more code than a flag.** Suspend, assign, find the thread, resume: about 30 lines of `x/sys/windows` in `internal/proxy`, a second importer of that package, and one more failure path at start (which fails closed). It is covered by the Windows CI job.
- **A macOS CI job** is added, which costs runner minutes on every pull request.

### Neutral

- `WaitDelay` stays, now as a backstop rather than the normal path.
- Exit-status attribution (T0.25) reads the leader's `Wait`, as today; a grandchild's exit is never reported as the upstream's.
- The in-memory, IO and stdio transports own no process and are unaffected. Streamable HTTP upstreams (none in M0) own no process either.
- Nothing changes for an upstream that is the server itself: its group or job has one member.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Leave it: document "point `--upstream` at the server" and keep the row open | The advice is easy to miss, desktop MCP configs are copied with `uvx` and `npx` in them, and the consequence is a live process holding credentials. The fix is small and uses a dependency already in `go.mod` |
| Linux `PR_SET_PDEATHSIG` (`SysProcAttr.Pdeathsig`) | It applies to the direct child only and is cleared in the child's children, so it does not reach the grandchild, which is the whole problem. It fires when the *thread* that forked exits, not the process (Go 1.26.8 `src/syscall/exec_linux.go:92-95`, go.dev/issue/27505), so it needs `runtime.LockOSThread` around the start inside go-sdk's `Connect`. Linux only. Its one benefit, covering a Fathomgate crash, is better covered by systemd |
| Linux cgroup v2 per upstream (`SysProcAttr.UseCgroupFD`, `exec_linux.go:107-108`; `cgroup.kill`) | The only Unix option that also catches `setsid` escapes. It needs a delegated, writable cgroup subtree, which an unprivileged process started by a desktop MCP host does not have, and a kernel with `cgroup.kill` (5.14+). Linux only, so macOS still needs the process group. Revisit for the container and service deployments of later milestones, where the runtime already provides the cgroup |
| Windows: assign to the job right after `Start`, without `CREATE_SUSPENDED` | Simpler, but it leaves the race open: a launcher that starts its child in its first milliseconds (a native redirector, a small script host) puts that child outside the job. A guarantee that holds only when the launcher is slow is not one |
| Windows: `PROC_THREAD_ATTRIBUTE_JOB_LIST` at `CreateProcess` | Atomic and the cleanest in principle, but `syscall.StartProcess` builds its own attribute list (parent process and handle list only, `exec_windows.go:398`, `424`) with no hook to add one. Using it means reimplementing process start outside `os/exec`, underneath go-sdk's `CommandTransport` |
| Windows: put Fathomgate itself in a job, so every child inherits it from `CreateProcess` | No race, and it covers crashes, but a job cannot be left: terminating it for the ADR 0018 restart would kill Fathomgate too. It could back up the per-process job, but adds nothing the per-process job with `KILL_ON_JOB_CLOSE` lacks |
| Let the operator opt in (`--upstream-kill-tree`) | A flag whose safe value is the only sensible one. Everything an upstream starts is part of the upstream; killing less is the defect |
| Use `exec.CommandContext` and `Cmd.Cancel` to kill the group | `Cancel` runs only when the command's context ends before the process exits (`src/os/exec/exec.go:276`). It does not see go-sdk's `SIGTERM` and kill on `Close`, nor a leader that already exited, so the shutdown and sweep paths still need their own code. It may still be how `killProcess` is wired; that is the owning engineer's choice |

## Amendments

This section records factual corrections (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | Windows, "so no descendant can leave it" and Negative's "on Windows a descendant can start processes outside the job only through another service" are wrong. Corrected: any descendant can start a process outside the job by naming a same-user process outside the job, Fathomgate included, as its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, Go's `SysProcAttr.ParentProcess`; one unprivileged call), or through a service (WMI, the Task Scheduler). A descendant that can open Fathomgate with `PROCESS_DUP_HANDLE` can also duplicate the job handle, so kill-on-close does not fire when Fathomgate dies. The job, like the Unix process group, contains launchers that do not try to escape; it is not a sandbox | L1 in the security review of PR #111 (T0.46), verified by the reviewer. The decision is unchanged: breakaway stays disallowed and the per-process job stays; the residual is recorded in the threat model |
| 2026-09-25 | Unix sweep: when the group has already been sent `SIGKILL`, the post-reap sweep sends `SIGKILL` again and returns, with no `SIGTERM` or grace. A setuid launcher's `EPERM` on a group signal is logged once at Warn | L3 and N2 in the same review: with Fathomgate as PID 1 and no init, zombies kept `kill(-pgid, 0)` succeeding, so every sweep waited its full 2 s; `EPERM` failed silently. install.md now tells container users to run with `docker run --init` |

## References

- [M0 board](../milestones/M0.yaml): T0.46 (this decision), T0.39 (the restart, where S2 was found), T0.34 (the server that never exits after its receive loop dies), T0.25 (exit status)
- [T0.39 security review handoff](../handoffs/2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.39.review.md): S2 and L1
- [ADR 0011, accept go-sdk and its transitive modules](0011-accept-go-sdk-transitive-modules.md) (gains an amendment row when the code lands)
- [ADR 0012, `netguard serve` flags and the `internal/proxy` API for M0](0012-serve-cli-and-proxy-api-for-m0.md)
- [ADR 0018, bound `server/discover`, then restart](0018-bound-server-discover-then-initialize-only.md) (second amendment row)
- [profile-schema 8.3, `fathomgate serve` flags](../specs/profile-schema.md#83-fathomgate-serve-flags)
- [Threat model](../security/threat-model.md), row "Orphaned grandchild after the ADR 0018 restart"; [SECURITY.md](../../SECURITY.md) line 76
- [install.md, point `--upstream` at the server, not at a launcher](../install.md#point---upstream-at-the-server-not-at-a-launcher)
- `internal/proxy/command.go` (`waitDelay`, `terminateDuration`, `Command`, `Command.Transport`); `internal/proxy/proxy.go` (`exitGrace`, `connectUpstream`, `connect`, `connectAttempt`, `trackedTransport`, `killProcess`, `kill`, `Proxy.Close`); `internal/proxy/stdio_test.go` (`TestMain` helper modes)
- go-sdk v1.8.0 `mcp/cmd.go`: `CommandTransport` (lines 20-47), `pipeRWC.Close` (lines 69-108)
- Go 1.26.8 standard library: `src/syscall/exec_linux.go` (`Setpgid`, `Pgid`, `Pdeathsig`, `UseCgroupFD`), `src/syscall/exec_libc2.go` (macOS `Setpgid`), `src/syscall/exec_windows.go` (`SysProcAttr`, `StartProcess`), `src/os/exec/exec.go` (`Cancel`, `WaitDelay`)
- `golang.org/x/sys` v0.48.0 `windows/zsyscall_windows.go`, `windows/types_windows.go`
- Microsoft: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), [`JOBOBJECT_BASIC_LIMIT_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information), [`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- Linux: [`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html) (`PR_SET_PDEATHSIG`), [`setpgid(2)`](https://man7.org/linux/man-pages/man2/setpgid.2.html), [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
