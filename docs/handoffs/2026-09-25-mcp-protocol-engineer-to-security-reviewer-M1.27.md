# M1-27: exclusive loopback binds and held wildcards on Windows; the squat while fathomgate is down stays open until M2

- **Task:** M1-27 — Bind listener sockets with SO_EXCLUSIVEADDRUSE on Windows; update the port-squatting threat-model row
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer second)
- **State now:** in review, code approved by the security and Go re-review; final wording round pushed. This PR leaves `docs/milestones/M1.yaml` alone (the orchestrator asked for no board or ADR edits), so the board still says `open`.
- **Branch / PR:** `fix/windows-exclusive-bind` · [PR #156](https://github.com/fathomgate/fathomgate/pull/156)
- **Date:** 2026-09-25

## Done

- `cmd/fathomgate/listen.go`:
  - `listenTCP` (`net.ListenConfig{Control: bindControl}`).
  - `bindLoopback(a, listen, hold, logger)`: after the loopback binds, `hold` takes the port on the wildcards. A failure closes everything and refuses, naming the address; for port 0 it retries on a new port. The listeners it returns (`heldListener`) close the held sockets once, on the first `Close`, so the shutdown path, the upstream-failure path and the `HTTPHandler` error path all release them.
  - `serve.go` passes `holdWildcards`.
- `listen_windows.go`:
  - `bindControl` sets `SO_EXCLUSIVEADDRUSE`.
  - `holdWildcards` binds `0.0.0.0:P`, `[::]:P` with `IPV6_V6ONLY` 1, and `[::]:P` with `IPV6_V6ONLY` 0, all through `WSASocket` with `WSA_FLAG_NO_HANDLE_INHERIT`. It sets no option and never listens. A family the host lacks is skipped.
- `listen_unix.go`, `listen_other.go`: `bindControl` and `holdWildcards` are nil.
- Tests:
  - Windows: `TestBindLoopbackExclusiveWindows` checks both loopbacks and all three wildcards, with and without `SO_REUSEADDR`, then that agents reach both addresses and that the wildcards are free after `Close`. `TestBindLoopbackRefusesHeldWildcardWindows` has one case per wildcard kind. Also `TestServeListenWildcardHeldWindows`, `TestHoldWildcardsNotInherited` and `TestBindControlFailsClosedWindows`.
  - All platforms: `TestBindLoopbackHoldInjected`. Linux: `TestBindLoopbackRefusesWildcardLinux`.
  - The squatters bind without listening, so there are no firewall prompts. The Windows and Linux CI H1 steps grep for each `--- PASS`.
- Docs: threat-model row and the MCP03/MCP07 map lines, `SECURITY.md`, profile-schema 8.5 Lifecycle, CHANGELOG Unreleased Security.
- Merged `origin/main`; STATUS.md re-rendered (no change).

## Look at this first

- `holdWildcards` in `listen_windows.go` and its doc comment. The wildcard sockets are bound after both loopbacks and **without** `SO_EXCLUSIVEADDRUSE`, as the review measured. My first attempt failed only because the guard had the option. Removing the three binds makes `TestBindLoopbackExclusiveWindows` and the two refusal tests fail (checked by hand).
- `heldListener` in `listen.go`: the first listener closed releases the wildcards. Every path that closes one listener closes them all.
- The threat-model row status, now split by case:
  - exact-address takeover on Windows: defence in depth;
  - wildcard squat while fathomgate runs on Windows: mitigated by design; measured only with same-user sockets; the other-user case, which is the threat, is to be measured;
  - squat while fathomgate is down: open until TLS on loopback in M2.

## Deliberately unfinished

- TLS on loopback, `--listen-remote` and `--listen-host` (M2).
- Another user's socket, on Windows or macOS: it needs a second account, and CI has none.
- `TestBindLoopbackRefusesWildcardLinux` was not run locally (Windows host); the Linux CI job runs it.
- The `golang.org/x/sys` "Why" text in ADR 0011 and in CLAUDE.md still names only the token DACL check for `cmd/fathomgate`. It now also misses the Winsock codes, the socket option and the wildcard sockets. Not edited: no ADR edits in this PR, and CLAUDE.md is the maintainer's.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && make policy-test && make fixtures-check
FATHOMGATE_REQUIRE_BOTH_LOOPBACKS=1 go test -count=1 -v -run 'TestBindLoopback|TestServeListen.*(Taken|Held)|TestBindControl|TestHoldWildcards' ./cmd/fathomgate/
GOOS=windows golangci-lint run ./... && GOOS=linux golangci-lint run ./... && GOOS=darwin golangci-lint run ./...
```

## Decisions made without an ADR

- The wildcard sockets are raw Winsock sockets (`WSASocket`, `Bind`), not `net.ListenConfig`, because the `net` package cannot bind a TCP socket without listening. `IPV6_V6ONLY` is set with `setsockopt` before bind rather than in a `Control` callback.
- `bindLoopback` gained a `hold` parameter, so the injected tests pass nil and cannot bind real wildcards.
- SO_REUSEPORT is the literal `0xf` in the Linux test (amd64 and arm64 only).

## Questions for the receiver

- Is naming the wildcard in the refusal (`[::]:P (dual-stack), a wildcard address on the same port, cannot be held`) clear enough for an operator, or should it say which program to look for (`netstat -ano`)?
