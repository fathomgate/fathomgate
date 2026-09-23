# T0.2 for security review: pass-through proxy forwards untrusted upstream tools with a `<server>.` prefix and no policy

- **Task:** T0.2 — internal/proxy — spawn one stdio upstream, forward tools/list and tools/call with server prefix
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also listed)
- **State now:** in review
- **Branch / PR:** `feat/proxy-passthrough`, stacked on PR #14 (T0.1, head `64bf8b7`) · no PR yet (not pushed)
- **Date:** 2026-09-23

## Done

- `internal/proxy` (new): `New` connects each upstream with a go-sdk client, lists its tools once and registers each as `<server>.<tool>`. `Run` serves the agent. `Close` stops the upstreams. `Command.Transport` spawns a stdio upstream with no shell and the proxy's environment plus `--upstream-env`.
- Unknown and unprefixed names are caught by receiving middleware before any handler runs: JSON-RPC `-32602` with `data.reason` set to `unprefixed`, `unknown_server` or `unknown_tool`. An exited upstream gives an `isError` tool result that names it. An upstream JSON-RPC error keeps its code, its message is prefixed `upstream <server>:`, and its `data` is dropped.
- Untrusted input handling: upstream tool names outside `[A-Za-z0-9_.-]` (spaces, ANSI escapes, look-alike Unicode) or over 128 characters once prefixed are not exposed. So are tools whose input schema is not `type: object` (go-sdk `AddTool` would panic; a `recover` backs up the check). The list is capped at 1024 tools. The upstream client advertises no roots, sampling or elicitation, so an upstream prompt cannot reach the agent unlabelled. Tool `_meta` and `icons` are dropped. Descriptions and annotations pass through unchanged and are not used for any decision.
- `cmd/netguard serve`: `--server`, `--upstream`, `--upstream-env`, upstream args after `--`. It refuses `--policy`, `--inventory`, `--profiles` and `--audit` with exit 2, so nobody runs M0 thinking a policy is enforced.
- `internal/tools/tools.go` is deleted and `go.mod` is unchanged. Docs: new profile-schema section 8 "Proxy config (M0)"; ADR 0012 (proposed); CLAUDE.md, ARCHITECTURE, README, ROADMAP and CHANGELOG updated; the tier 2 `conftest.py` now uses the new flags (tests still skipped).

## Look at this first

- `internal/proxy/proxy.go`: `forward` (error mapping), `checkToolName` and `unknownTool` (agent-controlled name echoed via `%q`, clipped to 200 bytes), and `addUpstreamTools` (which untrusted fields pass through).
- `cmd/netguard/serve.go`: the reserved-flag refusal and how the upstream env is built.

## Deliberately unfinished

- No policy, classification, redaction or audit. `Proxy.dispatch` is the M1 seam and is unexported, so it adds no new interface.
- Upstream results and error messages reach the agent unredacted. That is the same exposure as connecting to the upstream directly; redaction is M2.
- No TOFU pinning or quarantine (M2). `notifications/tools/list_changed` is ignored, so the list is frozen at startup, which also avoids an unpinned rug-pull.
- The agent's `_meta` is not forwarded. Dual-era and `_meta` handling are T0.3. go-sdk already negotiates on its own: the smoke agent got `2026-07-28`.
- `make conformance` is T0.4. `-race` and `goleak` could not run here (Windows, no cgo, and no `goleak` dependency without an ADR). Linux CI runs `-race`.
- Matrix row 1 is **not** validated. That is for the test-engineer against netdev-ssh-mcp.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=1 ./...     # -race on Linux CI
go build -o bin/netguard ./cmd/netguard
bin/netguard policy test $(find policies -name '*.test.yaml' | sort)      # 25/25
go test -count=1 -v -run 'Unknown|Exit|Cancel|Stdio' ./internal/proxy/
# Smoke (not validation): GOBIN=$PWD/gobin go install github.com/krisiasty/netdev-ssh-mcp@latest
#   then drive `bin/netguard serve --server netdev-ssh-mcp --upstream gobin/netdev-ssh-mcp` from any MCP client
```

## Decisions made without an ADR

- An upstream that exits leaves the proxy running and every call to it returns a tool error. The proxy does not exit. For one upstream, exiting would be the alternative.
- `serve` returns exit 1 when the upstream cannot start. It returns 2 only for usage errors.
- ADR 0012 covers the CLI surface and the exported proxy API, but it is **proposed**. Merge needs it accepted.

## Questions for the receiver

- Prefix: the spec (profile-schema section 1) and `tests/integration` say `netdev-ssh-mcp.run_show_command`. Matrix row 1 and PLAN.md say `netdev.run_show_command`. The code follows the spec. Should row 1 and PLAN be corrected (test-engineer and docs-writer), or should the profile's `server` key be renamed?
- Is relaying the upstream's JSON-RPC error message verbatim (labelled, `data` dropped) acceptable before redaction lands, or should M0 replace it with a fixed string?
- AGENTS.md says "don't implement `netguard serve` piecemeal", but T0.2, T0.3 and T0.4 are split on the board. Should the orchestrator reword it?
