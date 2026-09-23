# T0.3 ready for review: both eras negotiate through the proxy, no _meta crosses, upstream prompts reach the agent only labelled

- **Task:** T0.3 — Dual-era negotiation (initialize handshake vs _meta self-description, MRTR passthrough)
- **From → To:** mcp-protocol-engineer → go-reviewer, then security-reviewer
- **State now:** in review
- **Branch / PR:** `feat/proxy-dual-era` off `origin/land/m0-stack` (PR #25) · none yet (not pushed)
- **Date:** 2026-09-23

## Done

- **Era detection** (`internal/proxy/era.go`): go-sdk negotiates each side on its own. The upstream tries `server/discover`, then falls back to the initialise handshake at 2025-11-25. The agent's era is read per request. `upstream.version` and `call.agent.version` carry both eras to `Proxy.dispatch` for M1 audit, and `upstream ready` logs `protocol` and `era`.
- **`_meta`** (`proxy.go` `handler`, `forward`, `passResult`): nothing of the agent's `_meta` reaches the upstream. go-sdk injects the proxy's own triple and never overwrites existing keys, so forwarding would have leaked the agent's identity and capabilities. Upstream result `_meta`, and a stray `requestState` or `inputRequests` on a complete result, are dropped. This closes the "recheck in T0.3" row. A stateless agent sees netguard's own `serverInfo`.
- **Upstream prompts** (`input.go`): only form elicitation crosses to the agent. The message is prefixed `[from <server>] `, and every string in the message and schema is escaped. The schema must be flat. Limits: 16 requests per result, ids up to 128 bytes. Sampling, roots and URL mode are refused. Answers cross back only as `accept` (with content), `decline` or `cancel`, with no `_meta`.
  - Stateless agent: MRTR `input_required`.
  - Stateful agent: `elicitation/create`, looped by netguard itself, because go-sdk's server re-invokes only once.
  - Stateful upstream's `elicitation/create`: attributed to the only call in flight on that upstream, refused otherwise. Agent cancellation cancels the prompt.
  - 10 rounds per call.
- **`requestState`** (`state.go`): a stateless agent gets `ng1.<payload>.<sig>`. The HMAC-SHA256 uses a random per-process key and binds server, tool, argument digest, outstanding ids, the upstream's state (up to 64 KiB), the round and a 30-minute expiry. Bad retries get `-32602` with `invalid_request_state` or `invalid_input_responses`, and the upstream never sees them.
- **ADR 0014 (proposed), decision point:** ADR 0008 says a stateful upstream's `elicitation/create` is "converted to `input_required`" for a stateless agent. That needs the upstream call parked across agent requests. T0.3 refuses instead, with a labelled tool error. Everything else in ADR 0008 is implemented. No exported API changed (ADR 0012 holds).
- **Docs:** profile-schema §8.1 and §8.2 rows, new normative §8.4; SECURITY.md gap table (7 rows); CHANGELOG; ARCHITECTURE eras table; ROADMAP M0 line; `doc.go`; ADR index.

## Look at this first

- `internal/proxy/proxy.go` `forward`: the input loop, the refusal ordering and the era branch.
- `internal/proxy/input.go` `upstreamElicitation` and `refuse`: attribution through `upstream.calls`, and the `context.AfterFunc` cancel bridge.
- `internal/proxy/era_test.go` `legacyServer` and `legacyAgent`: how a go-sdk v1.7 fake is pinned to 2025-11-25.

## Deliberately unfinished

- **Stateless agent × stateful upstream prompt:** refused, pending the maintainer's decision on ADR 0014.
- **Not relayed:** progress notifications, and `_meta` inside content blocks (M2 serialiser).
- **HTTP:** there is no Streamable HTTP yet, so no `Mcp-Method`/`Mcp-Name` checks.
- **Row 2 not validated:** tier 1 fakes and a real stdio child only. Smoke against netdev-ssh-mcp v1.6.6 only. `upa/mcp-netmiko-server` was not run. The test-engineer validates.
- **Row 17:** labelling is implemented, but it is not validated against junos-mcp-server (M3).
- **`CLAUDE.md` repo map, line 88,** still says "dual-era is T0.3". Not edited, because it is agent configuration. Maintainer to update.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=3 ./...
go test -count=1 -v -run 'Era|MRTR|Refused|Round|NeedsOneCall|CancelDuringPrompt|Stdio' ./internal/proxy/
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golang:1.25 go test -race -count=3 ./...
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golangci/golangci-lint:v2.4.0 golangci-lint run ./...
go build -o bin/netguard ./cmd/netguard && bin/netguard policy test $(find policies -name '*.test.yaml' | sort)   # 25/25
python tools/status/render.py --check
```

## Decisions made without an ADR

- **Envelope parameters:** 30-minute TTL, per-process key (a restart voids outstanding states), 10 rounds, 16 requests, 64 KiB, and the argument digest over compacted raw bytes (not canonical JSON, so duplicate keys count). They are normative in §8.4, not in an ADR.
- **Refusal ordering:** an unattributable prompt is recorded against every call in flight on that upstream. A refusal is appended as text to an upstream result that still completes.
- **Upstream advertisement:** form elicitation is advertised to every upstream, because the agent's era is unknown at connect time.

## Questions for the receiver

- go-reviewer: is `upstream.calls` plus `refusedFor` after each `CallTool` the right shape, or should the refusal travel on the call's context?
- security-reviewer: is accepting replay of a valid envelope within its 30 minutes acceptable until M3 binds approvals to a pending id?
- Maintainer: accept ADR 0014 (refuse), or require parking before M0 closes?
