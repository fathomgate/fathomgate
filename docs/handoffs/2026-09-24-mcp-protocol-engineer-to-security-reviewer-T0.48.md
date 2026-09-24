# T0.48 ready for review: tampered requestState retries logged, unused progress owner fields removed, T0.30 review nits

- **Task:** T0.48: Apply the post-merge reviews of T0.30 (log tampered requestState retries, drop or use the unused progress owner fields, doc and test nits)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here. T0.48 is added to the board by #86, and the orchestrator syncs the board.
- **Branch / PR:** `fix/proxy-t030-review` · https://github.com/joshscott13/netguard/pull/88
- **Date:** 2026-09-24

## Done

- **L2 / Go 1, `internal/proxy/input.go` `resume`:** a retry whose `requestState` verifies (so it has the same transport and principal) but was issued for another tool or other arguments now calls `warnState` before the `-32602`.
  - The logged reasons are two fixed errors, `errStateOtherTool` and `errStateOtherArgs`. The line names neither the tool the state was issued for nor any argument.
  - The agent-facing detail is unchanged: it still names the prefixed tool the state was issued for, which was the agent's own call.
  - The same limiter applies, keyed by `"state"`, server, transport, principal and reason, with no tool. The `warnState` godoc now says so.
- **L1 / Go 2, `internal/proxy/progress.go`:** `progressRelay.sessionKey`, `transport` and `principal` are removed. Nothing but a test read them.
  - Choice: removal. No M4 audit need is concrete, since the audit line is built from `call`, which carries transport and principal.
  - The per-request guarantee is the upstream token plus the relay's own `session` and `ctx`. The `upToken` field comment says so.
  - `newProgressRelay` no longer draws a token. `watchProgress` draws it (`for r.upToken == "" || u.progress[r.upToken] != nil`).
- **`agentTransport`** (`state.go`) types `call.transport` and `stateBinding.transport`. `aad` and `warnState` convert to string explicitly.
- **`transportOf`** godoc states the fail-closed reading. `TestTransportOfFailsClosed` pins it:
  - no request, no Extra and empty Extra read as stdio with no principal;
  - header only reads as http with no principal;
  - a principal without the header reads as http with that principal;
  - a no-Extra binding cannot open an `{http, alice}` state.
- **Tests, `principal_test.go`:**
  - New: `TestTamperedRetryLogged`.
  - Changed: `TestProgressRelayPerSession`. It checks three relays on three distinct sessions and each agent's own progress. It uses a `gate` type (`sync.Once`), and a `t.Cleanup` opens every gate and waits on the WaitGroup.
  - Changed: `TestWatchProgressNeverSharesToken` (the token is drawn only in watch; the collision is forced after `a` is mapped).
  - Changed: the `TestCallCarriesTransportAndPrincipal` godoc.
  - `progress_test.go`: `TestProgressBucket` checks that no token exists before `watchProgress` and that the drawn one is at least 26 characters.
- **Godoc:** `refusalLimiter`, `refusalLogInterval` and `Proxy.refusalLog` name `warnState`.
- **Docs:**
  - ADR 0016: the T0.30 amendment row's progress sentence is reworded, and a new T0.48 amendment row is added.
  - profile-schema 8.2, the invalid-retry row: logging covers other tool and other arguments, the key is per reason, and the logged texts are listed.
  - profile-schema 8.4: at least 128 bits; the mapping keeps no owner record; `r<n>` covers every stateless request over the listener; *Accepted for M0* has the stateful-presents-stateless half sentence.
  - Threat model: the "Progress token scope" row is reworded. The "Cross-principal `requestState` replay" row gains the T0.48 logging, the two new tests and the full 30-minute same-token residual.
  - CHANGELOG `Unreleased` / Security: the T0.30 bullet is corrected and a T0.48 bullet added.

## Look at this first

- `internal/proxy/input.go`, `resume` and `warnState`. Check that nothing envelope-derived reaches the log. `st.Server` and `st.Tool` go only into the agent's detail, as before.
- `TestTamperedRetryLogged`. It fails with the `warnState` call removed from the arguments branch (checked, then reverted).

## Deliberately unfinished

- The ADR 0016 plan line "T0.30 only has to key the relay per session as well" (Consequences / board text) is left as written history. The amendment rows carry the correction.
- No log line for invalid `inputResponses` (`reasonInvalidInputResponse`). The review did not ask for one, and it is the agent's answer, not the state.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && python tools/status/render.py --check
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0 run ./...   # 0 issues
make conformance   # here: tests/conformance/run.sh <leg> <rev> for all 8 leg/rev pairs, plus era_pairs.py; all baselines pass, no baseline change
```

Local runs were on Windows without cgo, so `go test` ran without `-race` there. CI on the self-hosted WSL runners runs `-race`; the result is in a PR comment.

## Decisions made without an ADR

- Removal rather than a reader for the progress owner fields (the task preferred removal).
- The log's other-tool reason is generic (`issued for another tool`), while the agent still gets the prefixed name. The task asked for no values from the envelope in the log. The agent's detail was left alone to keep the wire form unchanged.
- `watchProgress` keeps a token already set on the relay when it is not mapped. Only tests set one, to force a collision. Production relays arrive with `""`.

## Questions for the receiver

- Is one limiter key per reason (not per tool) right for the two new reasons? A client that alternates tools with one state gets one `issued for another tool` line per 10 seconds, with `suppressed` counting the rest.
