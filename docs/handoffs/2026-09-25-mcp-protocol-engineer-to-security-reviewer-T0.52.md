# T0.52 ready for review: `--listen` binds both loopback families, plus the rest of the PR #109 reviews

- **Task:** T0.52 — Apply the post-merge security review of PR #109 (--listen binds both loopback families; port-squatting row; slot exhaustion; macOS ACLs; proxy export ADR)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `fix/listener-review` · see the PR that carries this note
- **Date:** 2026-09-25

## Done

- **H1 (high), `cmd/fathomgate/listen.go` `bindLoopback`:** binds the address asked for, then the other family's loopback on the port it got (`[::1]` for any IPv4 loopback, `127.0.0.1` for `[::1]`). Both are served by the one `http.Server`. Any failure of the second bind exits 1 before the upstream starts, naming the address and no token. The one exception is a missing loopback family: `EADDRNOTAVAIL`, `EAFNOSUPPORT` or `EPROTONOSUPPORT` on Unix, and WSA 10049, 10047 or 10043 on Windows (`listen_{unix,windows,other}.go`). That logs a warning and serves on one family; other platforms treat no error as a missing family. With port `0` a taken second port is retried with a new port, up to 8 times. One `listening url=...` line per address, the address asked for first. `localhost` stays accepted (still taken as `127.0.0.1`, never resolved), since binding both families covers whatever a client resolves it to. Reasoning and alternatives are in ADR 0023.
- **L1, `limitedConn.SetReadDeadline`:** the first read deadline on a new connection is capped at 3 s from accept (`firstHeaderTimeout`). In Go 1.26 that is `conn.serve`'s header deadline for the first request. Later requests keep `ReadHeaderTimeout` 10 s. `limitListeners` shares the 128 slots across both listeners. The residual (a local user reconnecting about 43 times a second) is recorded in row 34.
- **L2, `internal/fileacl` (new package):** `Extended(*os.File)` calls `fgetattrlist(2)` for `ATTR_CMN_EXTENDED_SECURITY` on the descriptor, through `syscall.Syscall6(SYS_FGETATTRLIST, …)`. That needs no cgo and no `x/sys/unix`. `parseAttrBuf` reads the `kauth_filesec` entry count in either byte order. On other OSes `Extended` returns false. Callers: `readTokenFile` (unix), and the audit's `createExclusive` (owner-only files; the new file is deleted when it inherited an ACL) and `checkLogFile` (an existing log). I checked the method first. I did not use the `com.apple.system.Security` xattr the brief suggested: XNU treats the `com.apple.system.` namespace as protected, and by my reading of its source an unprivileged `getxattr` on it fails. I could not confirm that on a Mac. `getattrlist` is the documented, unprivileged way the ACL is exposed, and it works on the open descriptor. A new `macos` CI job runs the tests with real `chmod +a` ACLs and fails unless each prints `--- PASS`.
- **L3:** [ADR 0022](../adr/0022-internal-proxy-export-surface.md) (proposed) lists the whole exported surface from `go doc ./internal/proxy` and says it changes only through a superseding record.
- **N1, N2, M1, row 55:** threat-model rows 38 (N1, plus L2 and its residuals), 39 (N2), 55 (listener shutdown and the exit-1 restart loop; the second signal) and 34 (L1). Two new rows are at the end of the table, so the existing row numbers still hold: the loopback family squat (Mitigated) and port squatting while down (Open, M1, owner mcp-protocol-engineer). The OWASP map lists both under MCP07, and port squatting under MCP03 too. SECURITY.md has a matching row.
- **N2 fix:** `serve` calls `context.AfterFunc(ctx, stop)` right after `NotifyContext`, so a second SIGINT or SIGTERM gets the default action.
- **Go review:** (1) `longLived` leaves `Mcp-Method: subscriptions/listen` out of the grace, like GET. (2) See N2. (3) `token_other_test.go`, and the FIFO case only where `syscall.Mkfifo` exists (`token_fifo_test.go` / `token_nofifo_test.go`). A `go vet` loop over every `go tool dist list` target (android and ios aside) is clean for `./cmd/... ./internal/...`. (4) `windows/arm64` is in `LINT_TARGETS`. (5) `TestListenerEndToEnd` asserts that 401 and 403 close the connection on both addresses through `cmd/fathomgate`'s real server. The T0.27 rule holds on this path, with no code change. The nits are all done: the `served` error variable, the `UpstreamExited` godoc, the "path with =" case, `t.Run` in every table named, and the usage line.
- **Docs:** ADR 0023 (proposed; amends ADR 0016's `--listen` row, limit 8, the J4 grace and signals), ADR index, profile-schema 8.3 and 8.5, install.md ("Remote agents over HTTP": both families, the two `listening` lines, paste the exact URL, restart at once, a second Ctrl+C), `docs/maintainers.md` (lint targets), CHANGELOG `Unreleased` (Changed and Security; the T0.31 Added entry corrected).

## Look at this first

- `cmd/fathomgate/listen.go` `bindLoopback` and `loopbackFamilyMissing`. The test `TestBindLoopbackHoldsBothFamilies` is the regression the review asked for: with the listener up, `net.Listen` on either family's loopback at its port fails. It fails when the second bind is dropped (checked by mutation, then reverted). So do `TestFirstHeaderTimeout` with the cap removed (10 s instead of 300 ms) and `TestShutdownWithListenStream` with the `Mcp-Method` clause removed.
- `internal/fileacl/extended_darwin.go`: I could not run it on this Windows host. The `macos` job in this PR is its first real run.

## Deliberately unfinished

- **M1 (port squatting while down):** code cannot close it in M0. It stays an Open row with install.md guidance.
- **`subscriptions/listen` today:** go-sdk answers a listen request on fathomgate at once, because the proxy declares no `listChanged`, so no listen stream is long-lived yet. The grace change is defensive. `TestShutdownWithListenStream` uses a stand-in handler that holds the POST open, because the real proxy cannot. The docs say so.
- **The audit's `LoadKey`:** it reads the private key with no owner or mode check on any OS. That is a separate gap from L2, found while wiring L2, and not fixed here. It is worth a board task (policy-engineer).
- **FreeBSD and illumos NFSv4 ACLs:** not read. Recorded as a residual in row 38.
- **ADR 0016's status line:** not touched. Once ADR 0023 is accepted, the maintainer may add a pointer row there.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
make lint            # now six targets, windows/arm64 included
make conformance     # all 8 legs pass their baselines (serve.go changed)
go test -count=1 -v -run 'Bind|FirstHeader|ShareSlots|ListenStream|LongLived|OtherFamily|FamilyMissing' ./cmd/fathomgate/
# macOS only:
go test -count=1 -v -run 'Extended|ParseAttrBuf|ReadTokenFile|Darwin' ./internal/fileacl/ ./cmd/fathomgate/ ./internal/audit/
```

Run locally on Windows 11 (no `make`, no cgo): each Makefile gate's commands were run by hand, and golangci-lint v2.9.0 is clean on all six targets. There was no `-race` here; CI's Linux job runs it.

## Decisions made without an ADR

- The 3-second first-request header timeout and the 8 port-0 attempts are constants in `cmd/fathomgate`, recorded in ADR 0023 and profile-schema 8.5 rather than exposed as options.
- `internal/fileacl` is a new internal package, not a pipeline stage and not an interface in CLAUDE.md's list. ARCHITECTURE.md's stage table does not list it, and CLAUDE.md's repo map was not edited (not mine to change).
- The macOS check makes a direct system call (`syscall.Syscall6`), not a libc call. Apple does not promise a stable system-call ABI. If a macOS release broke the call, `Extended` would return an error and every caller would refuse the file (fail closed), with `FATHOMGATE_LISTEN_TOKEN` still available.

## Questions for the receiver

- H1: is a warning, rather than a refusal, right for a host with no IPv6 loopback? A local attacker cannot make the family go missing, and refusing would break IPv4-only containers.
- L1: is 3 s low enough, or should the residual in row 34 be taken further (per-peer limits cannot tell local users apart on loopback)?
- N1: I accepted it for M0 in row 38, with a note to run fathomgate as a user of its own. Do you want it Open with an M1 owner instead?
