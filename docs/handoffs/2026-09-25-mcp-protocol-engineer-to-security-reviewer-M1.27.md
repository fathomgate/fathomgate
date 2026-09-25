# M1-27: SO_EXCLUSIVEADDRUSE on the Windows --listen sockets; the port-squatting row stays open, partly mitigated

- **Task:** M1-27 — Bind listener sockets with SO_EXCLUSIVEADDRUSE on Windows; update the port-squatting threat-model row
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer second)
- **State now:** in review. This PR leaves `docs/milestones/M1.yaml` alone (the orchestrator asked for no board or ADR edits), so the board still says `open`.
- **Branch / PR:** `fix/windows-exclusive-bind` · [PR #156](https://github.com/fathomgate/fathomgate/pull/156)
- **Date:** 2026-09-25

## Done

- `cmd/fathomgate/listen.go` `listenTCP` (`net.ListenConfig{Control: bindControl}`); `serve.go` binds through it.
- `listen_windows.go` `bindControl`: `SO_EXCLUSIVEADDRUSE` (`^windows.SO_REUSEADDR`), set before bind. If it cannot be set, the bind fails and fathomgate exits 1.
- `listen_unix.go` and `listen_other.go`: `bindControl` is nil. The comment on the Unix one explains why.
- Tests: `TestBindLoopbackExclusiveWindows`, `TestBindControlFailsClosedWindows`, `TestBindLoopbackRefusesWildcardLinux`. The H1 tests now bind through `listenTCP`, and the CI H1 steps grep for the new tests' PASS lines.
- Updated `docs/security/threat-model.md` (row "Port squatting…" and the OWASP map), `SECURITY.md`, profile-schema 8.5 Lifecycle, and the CHANGELOG Unreleased Security section.

## Look at this first

- The Windows measurements, in the threat-model row: on Windows 11 build 26200 with a same-user socket, the option does **not** stop `0.0.0.0:P` or `[::]:P` being bound while fathomgate runs. That socket gets the agents' connections once fathomgate stops. ADR 0029 decision 4 expected otherwise. Holding the wildcard from fathomgate itself also fails (`WSAEADDRINUSE`).
- `TestBindLoopbackExclusiveWindows`: the `getsockopt` read-back is the real regression check. On this build a `SO_REUSEADDR` takeover of the exact address failed with `WSAEACCES` even before the change.

## Deliberately unfinished

- TLS on loopback, `--listen-remote` and `--listen-host`: deferred to M2 by the maintainer.
- Another user's socket was not tested on Windows or macOS. It needs a second account, and CI has none.
- `TestBindLoopbackRefusesWildcardLinux` was not run locally (Windows host). The Linux CI job runs it.
- The `golang.org/x/sys` "Why" text in ADR 0011 and in CLAUDE.md names only the token DACL check for `cmd/fathomgate`. It already missed the Winsock codes in `listen_windows.go`, and now misses the socket option too. I left both alone: I was not to edit ADR files, and CLAUDE.md is the maintainer's.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && make policy-test && make fixtures-check
FATHOMGATE_REQUIRE_BOTH_LOOPBACKS=1 go test -count=1 -v -run 'TestBindLoopback|TestServeListenOtherFamilyTaken|TestBindControl' ./cmd/fathomgate/
GOOS=linux golangci-lint run ./... && GOOS=windows golangci-lint run ./...
make conformance
```

## Decisions made without an ADR

- The Windows residual is logged, not asserted, so a future Windows that refuses the wildcard bind does not fail CI. What the test does assert is that loopback connections still reach fathomgate while it runs.
- SO_REUSEPORT is the literal `0xf` in the Linux test (amd64 and arm64 only), because `syscall` does not define it and `x/sys/unix` is not a dependency.

## Questions for the receiver

- Should the row read "Open, partly mitigated", or is it only defence in depth, since this Windows build already refused the exact-address takeover?
- Does ADR 0029 decision 4 need a dated correction row from the maintainer?
