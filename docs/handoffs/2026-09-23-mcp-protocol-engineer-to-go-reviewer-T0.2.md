# T0.2 review fixes are in (G1–G10, S1–S6); go-reviewer re-review, then security-reviewer

- **Task:** T0.2 — internal/proxy — spawn one stdio upstream, forward tools/list and tools/call with server prefix
- **From → To:** mcp-protocol-engineer → go-reviewer (re-review), then security-reviewer
- **State now:** in review
- **Branch / PR:** `feat/proxy-passthrough`, stacked on PR #14 (T0.1, head `64bf8b7`) · no PR yet (not pushed)
- **Date:** 2026-09-23
- **Supersedes:** [the first T0.2 note](2026-09-23-mcp-protocol-engineer-to-security-reviewer-T0.2.md) (go-reviewer: request changes; security-reviewer: approve with nits)

## Done

- **S1, G5, G6:** `cmd/netguard/serve.go` now parses flags in `parseServe(args, w) (serveConfig, error)`. Leftover arguments are refused unless `--` came first. Leftovers are scanned for `--policy`, `--inventory`, `--profiles` and `--audit` (`-x`, `--x`, `--x=v`), with or without `--`. An invalid `--server` exits 2 before anything is spawned (`proxy.ValidateServerName`). Covered by the `TestParseServe` table and `TestRunDispatch`.
- **S2:** the upstream inherits only an allow-list (`baseEnv` in `command.go`; Unix and Windows sets as specified; case-insensitive on Windows), plus `--upstream-env` appended last. `TestStdioUpstreamRoundTripAndExit` shows that `NETGUARD_TEST_SECRET` and `AWS_SECRET_ACCESS_KEY` arrive `<unset>` in a real child process. `TestBaseEnv` is a table test.
- **S3:** `relayUpstreamError` (`sanitize.go`) keeps the `upstream <server>:` label and escapes C0, C1, DEL and invalid UTF-8 as `\uXXXX` text. It caps the upstream part at 512 bytes without splitting an escape. It keeps only -32700, -32600, -32601 and -32603 and maps everything else, -32602 included, to -32603. `TestRelayUpstreamError` has 14 rows.
- **S4:** `Command.StderrPrefix` and a line writer: each upstream stderr line becomes `upstream <server>: <escaped line>`. Tested in-process (`TestLineWriter`) and through a real child's stderr.
- **S5 / G4:** if `Client.Connect` fails after spawn, `killCommand` kills and reaps the process. `TestConnectFailureKillsUpstream` runs a raw peer that answers `initialize` with version `1999-01-01` and never exits on its own; the test asserts `ProcessState != nil`. `Command.Transport` also sets `WaitDelay` to 2s, so a grandchild holding stderr cannot hang reaping.
- **S6:** the upstream client runs with go-sdk MRTR auto-handling disabled. An `input_required` result becomes a tool error: "netguard refused an input request ... from upstream <server>". The upstream's prompt text is never shown (`TestUpstreamInputRequestRefused`).
- **G2:** stdlib leak check in `TestMain` (`leak_test.go`). After all tests it polls for up to 5s until no goroutine stack contains go-sdk, `internal/proxy` or `os/exec.(*Cmd)` frames, and fails with the stacks if one remains. The watcher uses `defer close(up.done)`.
- **G3:** the `block` handler signals after `<-ctx.Done()`, and the test waits on that signal.
- **G7:** a failed call waits up to 2s (`exitGrace`) on `up.done` before choosing its error text.
- **G8:** `Tools()` is removed; `New` logs `upstream ready` with the tool count.
- **G9:** the `Command` godoc covers Close behaviour, the Windows difference and grandchildren. **G10:** `errors.New` is used where there are no format args.
- **G1:** ADR 0012 now includes the environment allow-list, argument handling, stderr prefix and kill-on-failure. `Tools()` is gone and `ValidateServerName` / `StderrPrefix` are added. It stays **proposed**.
- **Prefix ruling:** PLAN.md (the row-1 line and the M0 checkbox) and test-matrix row 1 now say `netdev-ssh-mcp.run_show_command` / `netdev-ssh-mcp.get_config`. The test-engineer signs off on the row. The AGENTS.md "piecemeal" line is reworded. CLAUDE.md had no such line, so the new sentence was added under "How work moves".
- Spec (profile-schema sections 8.2 and 8.3), SECURITY.md (new "Proxy transport (M0) gaps" table) and CHANGELOG are updated to match.

## Threat model (from the security review; also in SECURITY.md)

| Threat | M0 status | Closes |
| --- | --- | --- |
| MCP03 tool poisoning via descriptions | Open | M2 TOFU pinning and quarantine |
| Argument parser differential (duplicate JSON keys) | Open | M1 `internal/normalize` must reject duplicate keys |
| Hung upstream | Accepted for M0 (agent cancellation reaches the upstream) | M1 per-call deadline |
| Payload size cap | Note | Revisit with M2 redaction |
| Upstream result `_meta` forwarded unchanged | Open | Recheck in T0.3 |

## Look at this first

- `cmd/netguard/serve.go` `parseServe`, and `internal/proxy/sanitize.go`.
- `internal/proxy/proxy.go` `forward` (error-path order: input request, ctx, JSON-RPC, closed/EOF/await-exit, generic) and `connectUpstream` (`killCommand`).

## Deliberately unfinished

- A final upstream stderr line without a newline is dropped (documented in section 8.3).
- Reserved names are refused even among the upstream's own arguments after `--`, as the reviewer asked. So an upstream with its own `--audit` flag cannot be given it in M0 (noted in ADR 0012).
- No `-race` or golangci-lint on this Windows host. Linux CI runs both.
- Matrix row 1 is still not validated.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=3 ./...   # proxy prints "goroutine leak check: ok" with -v
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/netguard
go build -o bin/netguard ./cmd/netguard && bin/netguard policy test $(find policies -name '*.test.yaml' | sort)   # 25/25
python tools/status/render.py --check
```

## Decisions made without an ADR

- Only `killCommand` touches the `*exec.Cmd`, reached through `*mcp.CommandTransport.Command`; `Command` itself stays a plain value.
- `serve -h` now exits 0 (flag.ErrHelp); other parse errors exit 2.

## Questions for the receiver

- Should `-race` in Linux CI be marked required for T0.2's merge? It could not run here.
- `.claude/agents/mcp-protocol-engineer.md` (lines 27 and 57), `.claude/agents/design-guardian.md` (line 62) and `design/preview.html` (line 589) still say `netdev.run_show_command`. They are agent config and design-owned files, so I left them for the orchestrator and design-guardian.
