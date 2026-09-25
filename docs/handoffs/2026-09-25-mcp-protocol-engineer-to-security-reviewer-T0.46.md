# T0.46 ready for review: the upstream's whole process tree is stopped (ADR 0021)

- **Task:** T0.46 — Kill the upstream's whole process tree so a launcher's grandchild cannot outlive a restart or shutdown (S2)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `feat/upstream-process-tree` · see the PR that carries this note. ADR 0021 is still `proposed` on `main`; PR #110 records its acceptance and must merge first.
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

## Decisions made without an ADR

- `treeSignalLag` (250 ms) after each go-sdk shutdown signal, where the ADR says "at the same points" (reason above).
- The sweep lives in `trackedConn.Close` rather than separately in `Proxy.Close` and the exit watcher; it therefore also runs after failed attempts, where the group has already been SIGKILLed and it returns at once.
- The launcher fixture relays the child's stdin and stdout through pipes (the child inherits only stderr), and also accepts child mode `1`; the ADR names `silent` and `nodiscover`. Relaying stdout is what lets the launcher's exit end the session for the exit-watcher case.
- `IsProcessInJob` is not in x/sys/windows v0.48.0, so the Windows test loads it from kernel32 with `NewLazySystemDLL`; test code only.

## Questions for the receiver

- Is 250 ms the right lag, or would you rather have the group signalled only once go-sdk's close has passed its signal (which would need a go-sdk hook we do not have)?
- A setuid launcher (`sudo`) makes `kill(-pgid)` return `EPERM`; the sweep then stops at once. Acceptable as "the operator chose that launcher"?
