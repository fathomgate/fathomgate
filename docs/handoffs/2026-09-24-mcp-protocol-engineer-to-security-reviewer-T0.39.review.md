# T0.39 review fixes are in PR #79 (PR #77 had merged): answered handshakes no longer restart, the budget bounds both attempts, the probe tests are deterministic

- **Task:** T0.39 — Stop netguard hanging at startup on upstreams that never answer server/discover (probe timeout, restart, straight to initialize); T0.25 rides along
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer)
- **State now:** in review
- **Branch / PR:** `fix/proxy-discover-review` · https://github.com/joshscott13/netguard/pull/79 (follows #77, merged at 4892231). This note replaces `2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.39.md`
- **Date:** 2026-09-24

## Done

- **S1 / Go #1 / S4 (blocking).** `trackedConn` in `internal/proxy/proxy.go` wraps go-sdk's plain connection and records, under `trackedTransport.mu`:
  - `closeRequested`, set in `Close` before delegating;
  - `closeDone`, and `reapedUnkilled` when that close returned before any kill;
  - a hang-up: a read or write that failed before any close or kill.

  A retry happens only when the bound expired with ctx live and `closeRequested` was false at the moment it expired. The watcher reads that flag before it cancels the attempt, so no close the expiry itself causes is counted. An exit status is reported only by `endedOnItsOwn`: a hang-up, then a reap within `exitGrace` with no kill before it.
- **Flags, not timestamps.** A first version compared `closeAt` with `expiredAt`. On Windows `time.Now()` returned the same value for both, so an answered upstream was restarted anyway. The orders are now flags set under the mutex.
- **S3 / Go #2.** `connectAttempt` is shared by both attempts. Each attempt has a cancel-cause context, a watcher on the expiry channel, and `context.AfterFunc(actx, killProcess)`. The startup budget therefore kills the process of the attempt in progress. `graceFor` is min(2 s, time left).
- **Go #3.** The `nodiscover` fake calls `time.Sleep(time.Hour)`, not `select {}`.
- **Flake in `TestDiscoverProbeRestartsStdioUpstream` (Go review of PR #79).** `Options.discoverWait` (a duration) is replaced by the test-only `Options.discoverExpired <-chan struct{}`. Production uses a `time.AfterFunc(discoverProbeTimeout)` channel, and the log and error text always say 5s. The tests now expire the bound at known points:
  - the in-memory silent upstream fires it once it has read `server/discover`;
  - the stdio restart test fires it after stderr shows "not reading any more";
  - `TestConnectFailureKillsUpstream` fires it after the badversion fake prints "stdin closed", which means go-sdk's own close has begun;
  - `TestStartupBudgetBoundsRestart` fires it at once.
- **Nits.** The godoc is reflowed. The `discoverExpired` and `NewTransport` godoc is updated. There is a comment on the `withExit` identity check.
- **Tests.** A rejected-answer case in `TestDiscoverProbe`. `TestConnectFailureKillsUpstream` asserts 1 build, `unsupported protocol version`, no warn line and no status. A `listerror` case asserts no status. `TestStartupBudgetBoundsRestart` asserts a 2 s budget returns within 3 s. Against the old `proxy.go` these failed: 2 processes and `exit status 1`; `exit status 0`; 7.0 s.
- **Docs.** ADR 0018 has two amendment rows. Profile-schema 8.3 and 8.4 are corrected to match. `docs/install.md` gets "Point `--upstream` at the server, not at a launcher", with a README summary. The threat model has an open S2 row.

## Fix round (re-reviews of PR #79, both approved)

1. **Hang-up means end of stream only** (Go should-fix, security N2). `trackedConn.Read` counts only `io.EOF` or `io.ErrUnexpectedEOF`. The new `garbage` fake prints a line that is not JSON-RPC and exits 0 once stdin closes. `TestStartupExitStatus/garbage` expects no status; on the previous code it reported `exit status 0`. A failed write still counts, because on a pipe it means the upstream's stdin is gone. Spec 8.3 now says this.
2. **No restart once startup has ended** (L2). After `first.kill(0)` and the warn line, `connect` returns if ctx is done and never calls `NewTransport`. `TestNoRestartAfterStartupEnds` has a logger cancel ctx at the warn line; on the previous code it built a second transport.
3. `Command.Transport` sets `TerminateDuration: terminateDuration` (5 s) explicitly. A comment explains why `exitGrace` (2 s) must stay shorter.
4. **N3.** The `tracksConn` comment names go-sdk v1.8.0's client-side assertions and why the wrapper hides none:
   - `clientConnection` at client.go:331/400: ioConn does not have it.
   - `hasSessionID` at client.go:554: promoted through the embedded `Connection`.
   - `cancellationPropagator` at transport.go:221: ioConn does not have it.

   CONTRIBUTING.md, "Bumping go-sdk", gains the `grep -n 'mcpConn.(' mcp/*.go` step. The optional batch behaviour test was not added.
5. The `discoverExpired` godoc says it is shared by every upstream in one `New` and is test-only.
6. **L1.** Spec 8.3, ADR 0018's second amendment row and the S2 threat-model row say startup can overrun the budget by up to `WaitDelay` (2 s) when a launcher's grandchild holds stderr, and that killing the tree removes this.
7. ADR 0018's first amendment row says the exact rule applies to the transports `tracksConn` wraps (command, stdio, IO, in-memory).
8. Godoc rewrapped at `proxy.go` (the `connect` and `trackedTransport` comments) and in `doc.go`. The `NewTransport` godoc and `doc.go` now say "within 5 seconds of starting the first connect, spawn included".
9. **Windows venv, verified locally.** `Scripts\python.exe` is a redirector: `sys.executable` reports the venv path, and it runs the base `python.exe` as a child process. I killed only the parent with `TerminateProcess`, as Go's `Process.Kill` does. The child died with it, for both a `python -m venv` venv and a `uv venv` venv (Python 3.13.15, Windows 11). `docs/install.md` gives the Windows path and records the check.

**For the orchestrator (N6):** after an initialize-only connect, the upstream's era label can be wrong. An upstream that answers `2026-07-28` to the 2025-11-25 `initialize` is logged as `era=stateless`, but its go-sdk session is stateful. Today only logs are affected. In M1 it becomes an audit-accuracy issue, because the audit line records the upstream era. It needs a task. N1 above is the same finding.

## Look at this first

- `connectAttempt`, `trackedConn.Close`, `failed`, `endedOnItsOwn` and `tracksConn` in `internal/proxy/proxy.go`. The wrapper applies only to `CommandTransport`, `InMemoryTransport`, `IOTransport` and `StdioTransport`, because it would hide go-sdk's unexported `clientConnection` on Streamable HTTP connections. For an unwrapped transport an expired bound always counts as unanswered, and no status is reported.

## Deliberately unfinished

- **S2 follow-up.** Killing a launcher can leave the real server running as a grandchild, with the same `--upstream-env-pass` credentials, next to the restarted copy. The fix is a process group on Unix and a Job Object on Windows. It needs an ADR, because ADR 0011 scopes `golang.org/x/sys` to `internal/audit`. The threat-model row is open with owner mcp-protocol-engineer. The orchestrator should add the task to the M0 board; `docs/milestones/M0.yaml` is not edited here. The operator mitigation is in install.md and the README.
- **N1.** An upstream connected with initialize only can still answer `2026-07-28`, and go-sdk accepts it. `upstream ready` would then log `era=stateless` for a session that is stateful: go-sdk ran the initialize handshake and holds a session. Only the log and audit label are wrong. Not fixed.
- `-race` cannot run locally (no gcc); CI runs it. PR #78 (open) touches `proxy.go`'s `Run` and `input.go`, not this code. Rebase if it merges first.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go test ./internal/proxy/ -count=5 -run 'TestDiscoverProbe|TestStartupExitStatus|TestStartupBudget|TestConnectFailure|TestExitStatus|TestStdioUpstream'
make conformance
```

## Decisions made without an ADR

- A hang-up is any failed read or write before a close or kill was requested, with the caller's ctx still live. A write failing on a dead pipe counts, because go-sdk may write before it reads the EOF.
- The 2-second "ended on its own" window runs from the hang-up to the first close's return (the reap).
- The test hook is a channel on `Options`, unexported, replacing the unexported duration. No exported surface changes.

## Questions for the receiver

- Is the `tracksConn` allow-list acceptable as the boundary for the new signal, given no HTTP upstreams exist in M0?
