# M1-19: the gate wired into Proxy.dispatch; tool errors, counters, decision line, annotations, schema narrowing

- **Task:** M1-19 — Wire the gate into Proxy.dispatch - tool errors on deny, decision log line, session counters, annotations from tools/list
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer; design-guardian for the proxy's own refusal texts)
- **State now:** in review
- **Branch / PR:** `feat/wire-gate` · [PR #167](https://github.com/fathomgate/fathomgate/pull/167)
- **Date:** 2026-09-25

## Done

- `internal/proxy/gate.go`: `Options.Gate` and the `Gate` interface (`Decide`, `Arguments`) over `internal/gate/seam`. `dispatch` forwards only on `Verdict.Forward`; otherwise it returns `Verdict.Error` as a tool error and makes no upstream call. With a nil gate the proxy behaves as M0.
- Forwarded arguments are re-encoded from the checked object (`reencode`). There is a 64 KiB cap (`default:bad_arguments`, `parse_error=too_large`). A panic becomes `default:internal_error`, and the log names only the panic's kind.
- Counters: `counterKey`, `sessionCounter` (distinct devices, one lock per key across the decision, a cap of 4,096 names). They are dropped when a stateful session ends (`http.go` settleSession, `Run`).
- `hints.go`: `readOnlyHint` is read from the raw `tools/list` answers on wrapped connections, so an absent hint stays nil. `destructiveHint` comes from go-sdk.
- `tools/list`: `narrowSchema` for closed tools. Upstream prompts are refused under a policy for closed tools (`input.go`, `proxy.go` forward).
- `internal/gate`: direct `UnnamedArgs`/`MalformedArgs` reads (L1). `Arguments(server, tool)`.
- Docs: ADR 0026 and ADR 0014 *Notes after acceptance*, the ADR 0022 pointer, profile-schema 8.1 and 8.2 (policy row and prompt row), policy-schema 5, ARCHITECTURE, threat model (the elicitation row mitigated; new rows for gate failure and counters), CHANGELOG, package doc.

## Look at this first

- `internal/proxy/gate.go` `decide`: the cap, the counter lock, the second decision for already-touched devices, and `reencode`.
- `internal/proxy/hints.go` together with `trackedConn.Read`/`Write` in `proxy.go`.
- Tests: `TestGateVerdictsOnTheWire`, `TestGateAnnotations`, `TestGateCountersPerKey`, `TestGateRefusesUpstreamPrompts`, `TestRealGateThroughProxy`.

## Deliberately unfinished

- `serve` still passes no gate. M1-20 adds `--policy` and `--no-policy` and builds `gate.New`.
- For an HTTP upstream transport the `readOnlyHint` raise is unavailable (nil hints, with a Warn). `serve` only spawns stdio upstreams.
- Test-matrix rows 3, 4 and 6 are exercised in-process only. They are validated against the real upstreams after M1-20 (M1-28).
- M1-12 (DELETE window) revisit: this PR adds no per-call deadlines, and the M1-12 residual is unchanged.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...   # -race in CI
go test -count=1 -v -run 'Gate|CounterKey|TouchedCap|DecisionLine|Reencode|RealGate' ./internal/proxy/
bin/fathomgate policy test policies/examples/*.test.yaml   # 45 of 45
python tools/licences/third_party.py --check && python tools/licences/spdx.py
# make conformance by hand: tests/conformance/run.sh <leg> <rev> for 4 legs x 2 revs, then era_pairs.py; all green, baselines unchanged
```

## Decisions made without an ADR

These are recorded in ADR 0026 and ADR 0014 *Notes after acceptance*, marked *(review)*:

- `Gate.Arguments` added to the interface, for ADR 0033 section 4.
- New reserved id `default:internal_error`, produced by the proxy only.
- Upstream prompts refused under a policy for closed tools. Relay continues with no policy or no profile.
- Counter key fallback: a stateful call with no nameable session is counted with its principal or the process (stricter).
- Proxy-side refusals carry class `EXEC_ARBITRARY` (unclassified).

## Questions for the receiver

- Is refusing every upstream prompt under a policy the right trade, or should answers be allowed through for tools with no named answer fields until a record decides?
- Should `default:internal_error` get a short record of its own, or is the ADR 0026 note enough?
