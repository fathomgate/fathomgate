# T0.31 ready for review: `fathomgate serve --listen` is live, loopback-only and token-authenticated

- **Task:** T0.31 — fathomgate serve --listen, repeatable --listen-token-file name=path, FATHOMGATE_LISTEN_TOKEN; refused M1 flags; MCPGODEBUG refusal; server limits, shutdown and upstream-exit handling
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer and release-engineer also review)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `feat/serve-listen` · see the PR that carries this note
- **Date:** 2026-09-25

## Done

- **`cmd/fathomgate/serve.go`:** `--listen`, `--listen-token-file NAME=PATH` (repeatable), `FATHOMGATE_LISTEN_TOKEN` (principal `env`), and `--listen-remote` and `--listen-host` refused with exit 2 (`reserved for M1`), with or without `--listen`. The M1 pipeline flags are refused as before. `serve` is now a signal wrapper around `serveContext`, so tests can stand a cancelled context in for SIGINT. Order before anything is bound or spawned: flags, address, tokens, `MCPGODEBUG` (S6: `checkListenEnvironment` now has its caller). Then the bind, so a busy port exits 1 without spawning, then `proxy.New`, then `runListener`. `parseFlagError` handles the one boolean flag.
- **`cmd/fathomgate/listen.go`:** `parseListenAddr` (loopback only; `localhost` bound as `127.0.0.1`; no errors quote the value); `newHTTPServer` with the limits already there plus the J4 grace; `requestTracker`; and `runListener`, which exits 0 on the signal, 1 on `UpstreamExited`, 1 on a listener error, then shuts down with the grace and closes the proxy.
- **`cmd/fathomgate/listen_token.go`, `token_{unix,windows,other}.go`:** the token sources and the owner-only file check. Unix: `O_NOFOLLOW|O_NONBLOCK`, then fstat: regular file, one link, euid owner, `perm&0o077 == 0`. Windows: `FILE_FLAG_OPEN_REPARSE_POINT`, disk file, not a reparse point or directory, one link, owner is the current user, `SE_DACL_PROTECTED`, and every allow ACE is the user or `SYSTEM` (deny ACEs pass; any other ACE type fails). Reads at most 4096 bytes, trims one `\n` or `\r\n`, applies the shape rules HTTPHandler uses, and refuses a duplicate name or token. Errors never quote a token, a path or an argument. Tokens are scrubbed from stderr through the existing `Redactor` as `[redacted:listen-token:<name>]`, kept apart from `cfg.secrets` so they are never given to the upstream.
- **`internal/proxy` (L1 from the T0.48 review):** `serveAuthed` marks the request context (`listenerKey`). `transportOf(ctx, req)` reads the mark as `http`. `newCall` takes ctx. `Proxy.handler` refuses any call that reads as `http` with no principal before it is keyed, admitted or dispatched, and logs it at error. New export `(*Proxy).UpstreamExited() <-chan struct{}`, closed once by the upstream watcher when the session ends while not closing.
- **Tests:** `TestParseListenAddr`, `TestLoadListenTokens`, `TestListenTokenRulesMatchHandler`, `TestServeListenRefusals` (23 cases: exit 2, the flag named, no token, path or refused value in stderr, `--listen-token` is an unknown flag, `MCPGODEBUG` set and empty), `TestServeListenBindFails`, `TestReadTokenFileUnix` / `TestReadTokenFileWindows`, `TestShutdownGrace` (finishes within the grace; cancelled at its end), `TestListenerEndToEnd` (a real loopback listener, go-sdk clients in both eras with a bearer token, tools/list and tools/call to an in-process upstream, 401 and 403, exit 0 on cancel, upstream closed), `TestListenerUpstreamExit` (exit 1 while a call is in flight), `TestServeListenProcess` (the full `serveContext` path with a real child upstream: `localhost:0` bound as 127.0.0.1, a token file, a call, exit 0; and an upstream that exits mid-serve, exit 1), `TestListenerCallWithoutExtra` and extended `TestTransportOfFailsClosed` (L1), `TestUpstreamExited`. `cmd/fathomgate`'s TestMain now runs the same stdlib goroutine-leak check as `internal/proxy`, and both are clean.
- **Docs:** CLI help (`serve -h` and `fathomgate` usage), `docs/install.md` "Remote agents over HTTP", profile-schema 8.3 (flags table) and 8.5 (*Command line*, *Lifecycle*, *Transport of a call*, *Environment*, *API*), SECURITY.md (a gap row for the listener, closing paragraph), threat model (the L1 residual in the cross-principal replay row is closed; new rows for token exposure, a dead upstream or stuck shutdown, and MCPGODEBUG; OWASP map), ADR 0016 (three amendment rows dated 2026-09-25), ADR 0012 (a pointer row), CHANGELOG `Unreleased` (Added and Security).

## Stdio and listener together: kept exclusive

ADR 0016 decides this (CLI table: "with `--listen`, fathomgate neither reads stdin nor writes stdout"; *Neutral*; *Alternatives*: "Serve stdio and HTTP at once"). I kept it. With `--listen`, no `Proxy.Run` is started, stdin is never read and stdout is never written. Running both in one process would add a risk that no document accepts: the local agent's `{stdio, ""}` binding and its `l<n>` orphan key would share an upstream's prompt attribution with network principals. It would also bring the two-lifecycle exit rule the ADR rejects. The L1 marker still went in, because the task asked for it and because `Proxy` can serve both (the tests do), so the binding no longer rests on the CLI keeping them apart.

## Look at this first

- `internal/proxy/http.go` `transportOf` and `serveAuthed`, and `proxy.go` `handler`: the refusal runs before `agentSessionKey` and `admit`. `TestListenerCallWithoutExtra` strips `Extra` with a middleware in both eras. It fails with the mark removed (checked, then reverted); the stateful case shows the mark survives go-sdk's detached session context.
- `cmd/fathomgate/token_windows.go` `checkTokenHandle`: the ACE walk, and that `SE_DACL_PROTECTED` is required, so a file whose inherited ACL happens to be owner-only is still refused.
- `cmd/fathomgate/listen.go` `newHTTPServer`: the grace counts every method but GET. A 2026 `subscriptions/listen` POST holds it for the full 5 s.

## Deliberately unfinished

- **T0.32:** conformance against the listener (auth-and-prefix shim, control leg on `everything-server -http`, deleting `relay.py`, the four baselines). The legs still go through `relay.py` to stdio, and all pass with no baseline change.
- **T0.33:** matrix row 23 (tier 2 over HTTP against netdev-ssh-mcp; Claude Code with `"type": "http"`), tested client snippets for README and install.md (the new install.md section says snippets will follow), and SECURITY.md gap rows beyond the one added here. `fathomgate serve --listen 127.0.0.1:0 --listen-token-file ci=<file>` prints `msg=listening url=...` for the harness to read.
- The upstream tag for T0.33 is the one tier 2 pins for netdev-ssh-mcp: v1.7.1 since T0.51 (`NETDEV_SSH_MCP_VERSION` in `tests/integration/conftest.py`).
- No `SO_EXCLUSIVEADDRUSE` on Windows. Only the same user could take over the port, and that user can already read the token file.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && gofmt -l .     # no -race locally: Windows without cgo; CI runs -race
golangci-lint run ./... ; GOOS=linux golangci-lint run ./... ; GOOS=darwin GOARCH=arm64 golangci-lint run ./...   # v2.9.0, 0 issues each
bin/fathomgate policy test $(find policies -name '*.test.yaml' | sort)   # 25 passed
# fixtures-check loop from the Makefile; python tools/licences/third_party.py --check; python tools/licences/spdx.py
uv run --with pyyaml python tools/status/render.py --check
tests/conformance/run.sh <leg> <rev>   # all 8 leg/rev pairs, then era_pairs.py; see the PR for output
go test ./cmd/fathomgate/ -run 'Listen|Shutdown|Token' -count=25   # no flakes locally
```

A manual smoke with the built binary on Windows followed install.md step 1. The inherited-ACL file got exit 2 naming `icacls`. After `icacls /inheritance:r /grant:r "%USERNAME%:F"` the file was accepted. The rest of the run: no token got 401, an `Origin` got 403, a 2026-era `tools/call` returned the upstream's echo, the upstream's `exit` tool gave exit 1 with the message, and the token appeared 0 times in stderr.

## Decisions made without an ADR

- **`(*Proxy).UpstreamExited`** is a new export, recorded as an ADR 0016 amendment row (plus a pointer in ADR 0012) under the orchestrator's K4 ruling. There was no export-free way to do this. `internal/proxy` type-asserts the upstream's `*mcp.CommandTransport` to kill the process and flush its stderr, so a wrapper in `cmd/fathomgate` would break both.
- `FATHOMGATE_LISTEN_TOKEN`'s principal is `env`. The env value is not newline-trimmed: whitespace is refused instead.
- The grace excludes GET streams. Otherwise every SIGINT with a 2025-era agent connected would take the full 5 s, and `TestShutdownWithStatefulGET` (G2) would fail. A call that is still running when the grace ends is cancelled by `Proxy.Close`, and a warn line is logged.
- `--listen-token-file` without `--listen` is exit 2. `FATHOMGATE_LISTEN_TOKEN` without `--listen` is ignored, because hosts often set variables broadly.

## Questions for the receiver

- A malformed `MCPGODEBUG` (for example `x`) makes go-sdk's `internal/mcpgodebug` `init` panic before any fathomgate code runs. Every command, `version` included, exits 2 with a stack trace. It fails closed and predates this task. Is a note in 8.5 and the threat model enough, or do you want an upstream issue?
- Should the Windows check also accept `BUILTIN\Administrators` in the DACL? It is refused today, like `internal/audit`'s key, so a file `icacls` left with an Administrators ACE is rejected with the fix command.
