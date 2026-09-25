# T0.46 ready for review: the upstream's whole process tree is stopped (ADR 0021)

- **Task:** T0.46 — Kill the upstream's whole process tree so a launcher's grandchild cannot outlive a restart or shutdown (S2)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `feat/upstream-process-tree` · see the PR that carries this note. ADR 0021 is `accepted` (PR #110, merged into this branch).
- **Date:** 2026-09-25

## Done

- **`internal/proxy/tree.go`, `tree_unix.go`, `tree_windows.go`, `tree_other.go`:** `procTree` with `prepareTree` (before start), `attachTree` (after start, before go-sdk's first write), `kill`, `terminate`, `sweep` (once) and `mirrorShutdown`. Unix: `Setpgid`, `kill(-pgid, …)`, no `x/sys/unix`. Windows: unnamed, non-inheritable job with `KILL_ON_JOB_CLOSE`, no breakaway flag; `CREATE_SUSPENDED`, `OpenProcess(PROCESS_SET_QUOTA|PROCESS_TERMINATE)`, assign, then Toolhelp32 thread snapshot and `ResumeThread`. `tree_other.go` keeps `wasip1`/`plan9` building.
- **`command.go`:** `Command.Transport` calls `prepareTree`; `Command`, `waitDelay` and `terminateDuration` godocs rewritten.
- **`proxy.go`:** `trackedTransport.tree`; `Connect` attaches the tree and fails closed (kills, reaps, returns `proxy: upstream process tree (ADR 0021): …`); `killProcess` kills the tree then the leader; `trackedConn.Close` runs `mirrorShutdown` around go-sdk's close and `sweep(exitGrace)` after it. Because go-sdk reaps only inside that close (including after a read EOF, `jsonrpc2` `updateInFlight`), this one hook covers shutdown, the exit watcher and every failed attempt. `kill` godoc rewritten.
- **Tests (`tree_test.go`, `tree_unix_test.go`, `tree_windows_test.go`, launcher fixture in `stdio_test.go`):** restart then Close (launcher ignores EOF and SIGTERM), Close with a launcher that exits on EOF (post-reap sweep), startup budget within budget + 1 s (was budget + `WaitDelay`), mid-session launcher exit (exit watcher), group membership (Unix), `IsProcessInJob` for child, leader and not the test process (Windows). The grandchild lingers and ignores SIGTERM. Negative control on Windows: with the tree disabled every case fails, the budget case at 5.0 s for 3 s.
- **CI:** new `macos` job (`go test (macos)`): vet, `go test ./...`, `go test -race ./internal/proxy/`. Not a required check.
- **Docs:** ADR 0011 amendment row and header, CLAUDE.md toolchain line, ADR 0018 amendment row, profile-schema 8.3, threat model row → Mitigated with residuals, SECURITY.md row closed, install.md bullet rewritten (kept, see below), README sentence, test-matrix T0.46 note, maintainers.md go-sdk bump check, CHANGELOG `Security`.

## Look at this first

- `trackedConn.Close` and `tree.go` `treeSignalLag`: the group is signalled 250 ms after go-sdk signals the leader, not at the same instant. If the group signal reached the leader first and it was reaped before go-sdk's own `Signal`/`Kill`, `pipeRWC.Close` would return "os: process already finished" instead of `Wait`'s result.
- `tree_windows.go` `attachTree`: the fail-closed path, and that `resumeProcess` errors when no thread of the PID is in the snapshot.

## Deliberately unfinished

- install.md keeps "point `--upstream` at the server" and the launcher bullet: ADR 0021 drops it for `uvx`, `npx`, `uv run` and shell scripts only after the tier 2 case and a manual check on each OS. Neither is done here.
- Tier 2 case (`uv run` in front of upa/mcp-netmiko-server on its own `uv.lock`, one server process after the restart): for the test-engineer (matrix row 2 or a new row).
- `Proxy.Close` still returns go-sdk's `Wait` error for an upstream it had to kill (`exit status 1`) or whose descendant held stderr (`exec: WaitDelay expired before I/O complete`); unchanged by this task, and the tests log it rather than assert it.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && gofmt -l .      # Windows, no -race locally; CI runs -race on Linux and the proxy on macOS
for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do GOOS=${t%/*} GOARCH=${t#*/} golangci-lint run ./...; done   # v2.9.0
go test -count=5 -run 'Tree|Restart|Startup|ConnectFailure|Stdio' ./internal/proxy/
tests/conformance/run.sh <leg> <rev>   # all 8 pairs, then era_pairs.py
uv run --with pyyaml python tools/status/render.py --check
```

## Fix round (security and Go reviews of PR #111)

Both reviews approved with fixes; one round, same branch, `main` had not moved.

- **L1:** wording only, no code. `tree_windows.go` `procTree` godoc, the threat-model residual, SECURITY.md, profile-schema 8.3 and CHANGELOG now say that any descendant can start a process outside the job by naming a same-user process outside the job, fathomgate included, as its parent, or through a service, and that `PROCESS_DUP_HANDLE` on fathomgate defeats kill-on-close. ADR 0021 gains an Amendments section (row 1) and an `Amended:` header line.
- **L2:** `attachFault` (an `atomic.Pointer[error]` in `tree.go`, set only by tests), checked in `attachTree` on Windows after the assignment and before the resume. `TestTreeAttachFailsClosed` (serial) checks four things: the error wraps the fault as `proxy: upstream process tree (ADR 0021): …`, there is one process and no restart, the process was reaped, and on Windows the marker file is absent. `TestResumeProcessExited` holds a handle across the exit, so the PID cannot be reused. Note: with `CREATE_SUSPENDED` removed, `TestTreeAttachFailsClosed` still passes, because the kill lands before the Go runtime reaches the marker write. The suspended start is proven by S2's test, not this one.
- **L3 + Go S5:** `procTree.killed` is set on a successful group SIGKILL. `sweep` then sends SIGKILL once more and returns with no grace. The sweep and the test `waitGone` use a timer and ticker. `TestProcTreeSweepAfterKill` sweeps an unreaped (zombie) group after `kill` and needs under 1 s against a 3 s grace. install.md "Running fathomgate in a container" documents `docker run --init`. The threat-model row names the PID-1 case and says what still waits: a sweep after the leader exited on its own.
- **N1:** the PID-reuse residual now names the sweep's poll window (up to 2 s, every 20 ms).
- **N2:** the setuid residual is recorded in the threat model, SECURITY.md, profile-schema 8.3 and CHANGELOG. `procTree.signal` logs the first EPERM once at Warn with `server` (the logger is `p.logger.With("server", …)`, now carried on `trackedTransport`) and `pgid`. `attachTree` takes that logger on every platform.
- **N5:** not touched; it is routed to T0.53 and the row points there.
- **Go S1:** `tree_test.go` is tagged `unix || windows`. The Getpgid test moved to `tree_pgid_test.go` (`linux || darwin || freebsd || netbsd || openbsd || dragonfly`). `stdio_test.go` no longer imports `os/signal` and `syscall`; it calls `ignoreSIGTERM` (`fixture_signal_test.go`, or the no-op in `fixture_signal_other_test.go`). `go vet ./internal/proxy/` with `CGO_ENABLED=0` passes on 42 of 47 `go tool dist list` ports, including plan9, js, wasip1, solaris, illumos and aix. The five others (android/386, android/amd64, android/arm, ios/amd64, ios/arm64) stop at "requires external (cgo) linking", before any code is checked. That predates this PR.
- **Go S2:** `TestTreeWindowsStartsSuspended` covers three stages. After `Start`, the main thread's suspend count is at least 1 (read with `SuspendThread` from kernel32 and undone with `ResumeThread`). After 500 ms there is still no marker. After `attachTree`, the marker appears and the process exits 0. Negative control (flag removed): it fails with "suspend count 0" and "the process ran before attachTree".
- **Go S3:** the ADR 0011 row, a new amendment row and CLAUDE.md name all three importers of x/sys/windows: `internal/audit`, `cmd/fathomgate` (`token_windows.go`, since T0.31, `b37a17f`) and `internal/proxy`. PR #112's `internal/fileacl` uses plain `syscall`, so it is not listed.
- **Go S4:** Unix `procWatch` is now a pointer holding an `os.Process` from `os.FindProcess`, which is pidfd-backed on Linux, and a sticky `gone` flag. Cleanup kills only if the watch never saw the process gone and it is still alive. Windows `procWatch` is a pointer too.
- **Nits:** the `treeSignalLag` godoc says best effort and names the failure mode ("os: process already finished", no wait, the last stderr lines lost). `waitGone` uses a ticker.
- **TestSealer:** the id is `FAKE-outstanding-id-otp` and the binding check is `"s":"s","t":"t","a":"` (20 bytes, asserted to be in the plaintext first). `-count=200` is clean.

## Decisions made without an ADR

- `treeSignalLag` (250 ms) after each go-sdk shutdown signal, where the ADR says "at the same points" (reason above).
- The sweep lives in `trackedConn.Close` rather than separately in `Proxy.Close` and the exit watcher; it therefore also runs after failed attempts, where the group has already been SIGKILLed and it returns at once.
- The launcher fixture relays the child's stdin and stdout through pipes (the child inherits only stderr), and also accepts child mode `1`; the ADR names `silent` and `nodiscover`. Relaying stdout is what lets the launcher's exit end the session for the exit-watcher case.
- `IsProcessInJob` is not in x/sys/windows v0.48.0, so the Windows test loads it from kernel32 with `NewLazySystemDLL`; test code only.

## Questions for the receiver

- Is 250 ms the right lag, or would you rather have the group signalled only once go-sdk's close has passed its signal (which would need a go-sdk hook we do not have)?
- A setuid launcher (`sudo`) makes `kill(-pgid)` return `EPERM`; the sweep then stops at once. Acceptable as "the operator chose that launcher"?
