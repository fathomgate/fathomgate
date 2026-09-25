# T0.52 ready for review: `--listen` binds both loopback families, plus the rest of the PR #109 reviews

- **Task:** T0.52 — Apply the post-merge security review of PR #109 (--listen binds both loopback families; port-squatting row; slot exhaustion; macOS ACLs; proxy export ADR)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `fix/listener-review` · see the PR that carries this note
- **Date:** 2026-09-25

## Done

- **H1 (high), `cmd/fathomgate/listen.go` `bindLoopback`:** binds the address asked for, then the other family's loopback on the port it got (`[::1]` for `127.0.0.1`, `127.0.0.1` for `[::1]`; since the fix round `--listen` takes only `localhost`, `127.0.0.1` or `[::1]`). Both are served by the one `http.Server`. Any failure of the second bind exits 1 before the upstream starts, naming the address and no token. The one exception is a missing loopback family: `EADDRNOTAVAIL`, `EAFNOSUPPORT` or `EPROTONOSUPPORT` on Unix, and WSA 10049, 10047 or 10043 on Windows (`listen_{unix,windows,other}.go`). That logs a warning and serves on one family; other platforms treat no error as a missing family. With port `0` a taken second port is retried with a new port, up to 8 times. One `listening url=...` line per address, the address asked for first. `localhost` stays accepted (still taken as `127.0.0.1`, never resolved), since binding both families covers whatever a client resolves it to. Reasoning and alternatives are in ADR 0023.
- **L1 (as first built; replaced in the fix round below):** the first read deadline on a new connection was capped at 3 s from accept (`firstHeaderTimeout`) in `limitedConn.SetReadDeadline`. Later requests keep `ReadHeaderTimeout` 10 s. `limitListeners` shares the 128 slots across both listeners. The residual (a local user reconnecting about 43 times a second) is recorded in row 34.
- **L2, `internal/fileacl` (new package):** `Extended(*os.File)` calls `fgetattrlist(2)` for `ATTR_CMN_EXTENDED_SECURITY` on the descriptor, through `syscall.Syscall6(SYS_FGETATTRLIST, …)`. That needs no cgo and no `x/sys/unix`. `parseAttrBuf` reads the `kauth_filesec` entry count in either byte order. On other OSes `Extended` returns false. Callers: `readTokenFile` (unix), and the audit's `createExclusive` (owner-only files; the new file is deleted when it inherited an ACL) and `checkLogFile` (an existing log). I checked the method first. I did not use the `com.apple.system.Security` xattr the brief suggested: XNU treats the `com.apple.system.` namespace as protected, and by my reading of its source an unprivileged `getxattr` on it fails. I could not confirm that on a Mac. `getattrlist` is the documented, unprivileged way the ACL is exposed, and it works on the open descriptor. A new `macos` CI job runs the tests with real `chmod +a` ACLs and fails unless each prints `--- PASS`.
- **L3:** [ADR 0022](../adr/0022-internal-proxy-export-surface.md) (accepted by the maintainer 2026-09-25) lists the whole exported surface from `go doc ./internal/proxy` and says it changes only through a superseding record.
- **N1, N2, M1, row 55:** threat-model rows 38 (N1, plus L2 and its residuals), 39 (N2), 55 (listener shutdown and the exit-1 restart loop; the second signal) and 34 (L1). Two new rows are at the end of the table, so the existing row numbers still hold: the loopback family squat (Mitigated) and port squatting while down (Open, M1, owner mcp-protocol-engineer). The OWASP map lists both under MCP07, and port squatting under MCP03 too. SECURITY.md has a matching row.
- **N2 fix:** `serve` calls `context.AfterFunc(ctx, stop)` right after `NotifyContext`, so a second SIGINT or SIGTERM gets the default action.
- **Go review:** (1) `longLived` leaves `Mcp-Method: subscriptions/listen` out of the grace, like GET. (2) See N2. (3) `token_other_test.go`, and the FIFO case only where `syscall.Mkfifo` exists (`token_fifo_test.go` / `token_nofifo_test.go`). A `go vet` loop over every `go tool dist list` target (android and ios aside) is clean for `./cmd/... ./internal/...`. (4) `windows/arm64` is in `LINT_TARGETS`. (5) `TestListenerEndToEnd` asserts that 401 and 403 close the connection on both addresses through `cmd/fathomgate`'s real server. The T0.27 rule holds on this path, with no code change. The nits are all done: the `served` error variable, the `UpstreamExited` godoc, the "path with =" case, `t.Run` in every table named, and the usage line.
- **Docs:** ADR 0023 (accepted by the maintainer 2026-09-25; amends ADR 0016's `--listen` row, limit 8, the J4 grace and signals), ADR index, profile-schema 8.3 and 8.5, install.md ("Remote agents over HTTP": both families, the two `listening` lines, paste the exact URL, restart at once, a second Ctrl+C), `docs/maintainers.md` (lint targets), CHANGELOG `Unreleased` (Changed and Security; the T0.31 Added entry corrected).

## Fix round (reviews of PR #112)

Security confirmed H1 closed on Windows and Linux by probing it. Both reviews asked for changes; none was high. Applied on the same branch:

- **Security 1 (medium), CI proof of H1:** `FATHOMGATE_REQUIRE_BOTH_LOOPBACKS=1` turns the skip in `needBothLoopbacks` (and the one-family fallback in `loopbackFamilies`, used by `TestListenerEndToEnd` and `TestServeListenProcess`) into a failure. It follows the `FATHOMGATE_REQUIRE_PRIVILEGED_TESTS` pattern and is set in the Linux `go`, `windows` and `macos` jobs. Linux and Windows each get an "H1 loopback tests ran" step: `-v` for `TestBindLoopbackHoldsBothFamilies`, `TestBindLoopbackRefusesTakenOtherFamily` and `TestServeListenOtherFamilyTaken`, then a `--- PASS` grep for each. The `macos` job now runs `go test -count=1 ./cmd/fathomgate/` in full, and its `-v` step greps for the same three tests next to the ACL tests.
- **Security 2 (low), `--listen 127.0.0.x`:** I narrowed rather than binding a third address. `parseListenAddr` takes only `localhost`, `127.0.0.1` or `[::1]`; any other `127.0.0.0/8` address exits 2 with `--listen takes localhost:<port>, 127.0.0.1:<port> or [::1]:<port>`. Narrowing is simpler to state and test, and a `listening` URL on `127.0.0.2` would be one no client reaches through `localhost`. ADR 0023 (point 1, *Negative*, alternatives), the flag help, the `parseListenAddr` comment, row 57, profile-schema 8.3 and 8.5, install.md, SECURITY.md and CHANGELOG say so. Tests: `TestParseListenAddr` (`127.10.20.30`, `127.0.0.2`, `127.0.1.1` refused) and a `TestServeListenRefusals` case.
- **Security 3, threat-model notes:** row 58 records the Windows wildcard bind (`0.0.0.0:P` or `[::]:P` while fathomgate runs, then wait; `SO_EXCLUSIVEADDRUSE` noted for M1). Row 57 records the macOS `fe80::1%lo0 localhost` hosts entry and Debian's `127.0.1.1` host name as residuals. Row 38 records SMB and NFS mounts that report no ACL. The MCP08 line of the OWASP map now names what this PR touches.
- **Security 4:** the audit `LoadKey` finding is left for its own board task.
- **Go B1, flaky `TestLimitListenersShareSlots`:** each listener's goroutine now accepts once, so the one that just accepted cannot take the freed slot again. It passed `-count=100` locally. The `limitListeners` godoc says an idle listener's Accept holds one shared slot while it waits.
- **Go B2, wall-clock waits:** `TestFirstRequestTimer` has no clock. It drives `ConnContext` with an injected `afterFunc` over `net.Pipe`, checks the timer length, fires it (the connection closes), and checks that the handler sees the timer stopped on entry, once across two requests, and that `firstHeader` 0 starts none. One real-socket smoke test is left, `TestFirstHeaderTimeoutSmoke`, with only an upper bound (half of `ReadHeaderTimeout`). `waitURLs` uses the `done`/`time.After` select that `waitListening` uses.
- **Go S1:** `bindLoopback` takes the port from `first.Addr().(*net.TCPAddr)`. If the address is not a `*net.TCPAddr` or names no port, it closes the listener and returns an error; a `TestBindLoopbackInjected` case covers it.
- **Go S2, the header-cap hook:** replaced. `newHTTPServer` starts `time.AfterFunc(firstHeader, conn.Close)` in `http.Server.ConnContext`, and `firstRequestSeen` stops it on the connection's first request, which net/http hands to the handler only once the headers are read. The design uses only documented hooks, so it does not depend on the order of `SetReadDeadline` calls, and it works under TLS. `limitedConn` no longer overrides `SetReadDeadline`. A slow first body is not timed, because the timer stops before the handler reads it. A timer that fires just as the request reaches the handler closes that connection (recorded in ADR 0023). I mutation-checked the test: without `seen()` it fails.
- **Go S3, the darwin call:** checked in the Go 1.26.8 source. `syscall/syscall_darwin.go` declares `Syscall6` without a body. `syscall/asm_darwin_arm64.s` implements it with `SVC $0x80`, and `asm_darwin_amd64.s` with `SYSCALL` on the number plus `0x2000000`. The libc trampolines in `runtime/sys_darwin.go` are used by the generated wrappers, not by `Syscall6`. So it is a raw trap, and the failure modes are:
  - An error return refuses the file.
  - A number the kernel no longer has makes it deliver SIGSYS. `runtime/signal_darwin.go` marks SIGSYS `_SigThrow`, so fathomgate crashes and nothing is accepted.
  - A number reused by another call that succeeds without filling the buffer is now refused. `parseAttrBuf` rejects a total length below the header or past the buffer; before this round, a zeroed buffer would have read as "no ACL". Cases "buffer never written" and "length past the buffer" cover it.

  The code comment, row 38 and this note say this. darwin/amd64 is linted but not run (the macOS runner is arm64), a residual in row 38 and the `macos` job comment.
- **Go nits:**
  - `listen_windows.go` and its test use `windows.WSAE*`.
  - The refusal names the address once: it unwraps `net.OpError`, so the text reads `[::1]:P, the other loopback address on the same port, cannot be bound (bind: ...)`.
  - `limitedConn.CloseWrite` forwards to the TCP connection (`TestLimitedConnCloseWrite`).
  - `TestLoopbackFamilyMissing{Unix,Windows}` use `t.Run`.
  - A compile-time check keeps `attrList` at 24 bytes.
  - `limitedListener`, `limitedConn` and `requestTracker.add` have doc comments.
  - ARCHITECTURE.md names `internal/fileacl`.

  I did not edit CLAUDE.md's repo map: an agent message cannot authorise changes to CLAUDE.md, so that line waits for the maintainer.
- **ADRs 0022 and 0023:** marked accepted on the coordinator's word that the maintainer accepted them on 2026-09-25. That covers the index rows, the `Amended by` line and pointer rows in ADR 0016, and a pointer row in ADR 0012.

Re-run after the round: `go build`, `go vet` and `go test ./...` pass. `go vet` passes on every GOOS/GOARCH (android and ios aside). golangci-lint v2.9.0 is clean on all six targets. Policy tests, fixtures, licences, SPDX and `render.py --check` pass. All 8 conformance legs pass. `FATHOMGATE_REQUIRE_BOTH_LOOPBACKS=1 go test -v` for the three H1 tests shows `--- PASS` on this Windows host.

## Look at this first

- `cmd/fathomgate/listen.go` `bindLoopback` and `loopbackFamilyMissing`. The test `TestBindLoopbackHoldsBothFamilies` is the regression the review asked for: with the listener up, `net.Listen` on either family's loopback at its port fails. It fails when the second bind is dropped (checked by mutation, then reverted). So do `TestFirstRequestTimer` without `seen()` and `TestShutdownWithListenStream` with the `Mcp-Method` clause removed.
- `internal/fileacl/extended_darwin.go`: I could not run it on this Windows host. The `macos` job in this PR ran it first (arm64 only).

## Deliberately unfinished

- **M1 (port squatting while down):** code cannot close it in M0. It stays an Open row with install.md guidance.
- **`subscriptions/listen` today:** go-sdk answers a listen request on fathomgate at once, because the proxy declares no `listChanged`, so no listen stream is long-lived yet. The grace change is defensive. `TestShutdownWithListenStream` uses a stand-in handler that holds the POST open, because the real proxy cannot. The docs say so.
- **The audit's `LoadKey`:** it reads the private key with no owner or mode check on any OS. That is a separate gap from L2, found while wiring L2, and not fixed here. It is worth a board task (policy-engineer).
- **FreeBSD and illumos NFSv4 ACLs:** not read. Recorded as a residual in row 38.
- **ADR 0016:** its status line is unchanged; since the maintainer accepted ADRs 0022 and 0023 on 2026-09-25, it has an `Amended by` line and pointer rows for both, and ADR 0012 has a pointer row for ADR 0022 (fix round).

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
make lint            # now six targets, windows/arm64 included
make conformance     # all 8 legs pass their baselines (serve.go changed)
FATHOMGATE_REQUIRE_BOTH_LOOPBACKS=1 go test -count=1 -v -run 'Bind|FirstRequest|FirstHeader|ShareSlots|CloseWrite|ListenStream|LongLived|OtherFamily|FamilyMissing' ./cmd/fathomgate/
# macOS only:
go test -count=1 -v -run 'Extended|ParseAttrBuf|ReadTokenFile|Darwin' ./internal/fileacl/ ./cmd/fathomgate/ ./internal/audit/
```

Run locally on Windows 11 (no `make`, no cgo): each Makefile gate's commands were run by hand, and golangci-lint v2.9.0 is clean on all six targets. There was no `-race` here; CI's Linux job runs it.

## Decisions made without an ADR

- The 3-second first-request header timeout and the 8 port-0 attempts are constants in `cmd/fathomgate`, recorded in ADR 0023 and profile-schema 8.5 rather than exposed as options.
- `internal/fileacl` is a new internal package, not a pipeline stage and not an interface in CLAUDE.md's list. ARCHITECTURE.md's stage table does not list it, and CLAUDE.md's repo map was not edited (not mine to change).
- The macOS check makes a raw system call (`syscall.Syscall6` is `SVC $0x80` / `SYSCALL` in Go 1.26, not libc's `syscall()`). Apple does not promise that ABI. The failure modes are in the fix round below; each fails closed, one of them by crashing.

## Questions for the receiver

- H1: is a warning, rather than a refusal, right for a host with no IPv6 loopback? A local attacker cannot make the family go missing, and refusing would break IPv4-only containers.
- L1: is 3 s low enough, or should the residual in row 34 be taken further (per-peer limits cannot tell local users apart on loopback)?
- N1: I accepted it for M0 in row 38, with a note to run fathomgate as a user of its own. Do you want it Open with an M1 owner instead?
