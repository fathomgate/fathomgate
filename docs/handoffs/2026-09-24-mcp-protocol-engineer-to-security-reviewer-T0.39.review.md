# T0.39 review fixes are in a new PR (PR #77 had merged): answered handshakes no longer restart, the budget bounds both attempts

- **Task:** T0.39 — Stop netguard hanging at startup on upstreams that never answer server/discover (probe timeout, restart, straight to initialize); T0.25 rides along
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer)
- **State now:** in review
- **Branch / PR:** `fix/proxy-discover-review` · see the PR titled "fix(proxy): apply the PR #77 security and Go reviews (T0.39)"; follows #77 (merged at 4892231). This note replaces `2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.39.md`
- **Date:** 2026-09-24

## Done

- **S1 / Go #1 / S4 (blocking).** `trackedConn` in `internal/proxy/proxy.go` wraps go-sdk's plain connection. It records when a close was first requested (`closeAt`) and when it returned (`closeDone`), and a hang-up: a read or write that failed before any close or kill. The retry happens only when the bound ran out with ctx live and `closeAt` is unset or after the deadline (`closeBegunBefore`). An exit status is reported only by `endedOnItsOwn`: a hang-up, reaped within `exitGrace` of it, and not after a kill.
- **S3 / Go #2.** `connectAttempt` is shared by both attempts. It runs `context.AfterFunc(ctx, killProcess)`, so the startup budget kills the process of the attempt in progress. `graceFor` is min(2 s, time left).
- **Go #3.** The `nodiscover` fake calls `time.Sleep(time.Hour)`, not `select {}`.
- **Nits.** The godoc at `proxy.go` 35-41 and `doc.go` 17-24 is reflowed. The `discoverWait` godoc now says it is test-only. The `NewTransport` godoc now says that reusing a transport makes the restart fail. There is a comment on the `withExit` identity check.
- **Tests.** A rejected-answer (`badVersionAttempt`) case in `TestDiscoverProbe`. `TestConnectFailureKillsUpstream` now uses a rebuildable transport and asserts 1 build, `unsupported protocol version`, no warn line and no status. A `listerror` case (a tools/list JSON-RPC error, then a clean exit 0) asserts no status. `TestStartupBudgetBoundsRestart` is adapted from your SEC-2, with the `silent` fake. Against the old `proxy.go`, three of these fail as the review described: 2 processes and `exit status 1`; `exit status 0`; 7.0 s on a 2 s budget.
- **Docs.** ADR 0018 gains an `Amendments` section with two rows: the exact retry rule, and how the budget is enforced. Profile-schema 8.3 and 8.4 are corrected to match. `docs/install.md` gets "Point `--upstream` at the server, not at a launcher", and the README a short version of it. The threat model gets an open row for S2.

## Look at this first

- `trackedTransport.failed`, `endedOnItsOwn` and `connectAttempt`, and `tracksConn`. The wrapper is applied only to `CommandTransport`, `InMemoryTransport`, `IOTransport` and `StdioTransport`. A wrapper would hide the unexported `clientConnection` method go-sdk finds on Streamable HTTP connections. For an unwrapped transport, an expired bound always counts as unanswered and no status is reported.

## Deliberately unfinished

- **S2 follow-up.** Killing a launcher can leave the real server as a grandchild. It keeps running with the same `--upstream-env-pass` credentials next to the restarted copy. The fix is a process group on Unix and a Job Object on Windows. That needs an ADR, because ADR 0011 scopes `golang.org/x/sys` to `internal/audit`. The threat-model row is open with owner mcp-protocol-engineer. The orchestrator should add the task to the M0 board; `docs/milestones/M0.yaml` is not edited here. Operator mitigation is in install.md and the README.
- **N1.** An upstream connected with initialize only can still answer `2026-07-28` to a 2025-11-25 `initialize`. go-sdk accepts any version it supports, so `upstream ready` would log `era=stateless` for a session that is actually stateful: go-sdk ran the initialize handshake and holds a session. Only the log and audit label are wrong. Behaviour follows go-sdk's session. Not fixed.
- `-race` cannot run locally (no gcc); CI runs it.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go test ./internal/proxy/ -count=5 -run 'TestDiscoverProbe|TestStartupExitStatus|TestStartupBudget|TestConnectFailure|TestExitStatus|TestStdioUpstream'
make conformance
```

## Decisions made without an ADR

- A hang-up is any failed read or write before a close or kill was requested, with the caller's ctx still live. A write that fails on a dead pipe counts, because go-sdk may write before it reads the EOF.
- The 2-second "ended on its own" window is measured from the hang-up to the return of the first close (the reap), not from when `kill` starts.

## Questions for the receiver

- Is the transport allow-list in `tracksConn` acceptable as the boundary for the new signal, given no HTTP upstreams exist in M0?
