# Upstream era now follows the handshake go-sdk completed as well as the negotiated version (N6), ready for security review

- **Task:** M1-06: Label the upstream era from the negotiated protocol version, not from how fathomgate connected (N6)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review
- **Branch / PR:** `fix/era-label-negotiated` · https://github.com/fathomgate/fathomgate/pull/151
- **Date:** 2026-09-25

## Done

- `internal/proxy/era.go`: `handshakes` is a sending middleware on the upstream's `mcp.Client`. It marks each session whose `initialize` request was answered without error. `take(cs)` reads the mark once and empties the map, so a failed first attempt's session is not kept. `upstreamEra(version, handshake)`: if the handshake ran, the session is stateful, whatever version the upstream answered. Otherwise the era is `eraOf(version)`.
- `internal/proxy/proxy.go`: new field `upstream.era`, set once in `connectUpstream`. The `upstream ready` line logs it. The `call` doc tells M1's audit to read `up.era`.
- Tests: `TestUpstreamEra`; two new `TestDiscoverProbe` rows (fallback answered with 2026-07-28, restart answered with 2026-07-28), and era plus ready-line checks on every success row; tier 1 `TestRestartedStdioUpstreamAnswering2026IsStateful` over a real stdio child (fake mode `nodiscover2026`, wrapper `initializeAnswers` in `stdio_test.go`); era checks in `TestEraMatrix`, `TestStdioUpstreamEras` and `TestDiscoverProbeRestartsStdioUpstream`.
- Docs: profile-schema 8.4 (Era detection, and the line on both versions riding with the call); CHANGELOG Unreleased, Fixed.

## Look at this first

- `handshakes.middleware` and `upstreamEra` in `internal/proxy/era.go`. The label comes from what go-sdk sent and had answered on the session. The upstream cannot set it by the version it names. A 2026-era upstream can only get `era=stateless` if go-sdk completed `server/discover` with it. It cannot get it by answering `initialize` with 2026-07-28. It can still claim a stateful session is 2026-07-28 (`protocol`), and that value is logged as the upstream answered it.

## Deliberately unfinished

- Such an upstream is not refused. fathomgate asked for 2025-11-25, and the upstream answered 2026-07-28. go-sdk accepts that and adds `_meta` to every request on the session (`usesNewProtocol` keys on the version). The session is a hybrid, and it is labelled stateful because server-initiated requests remain possible. Refusing it, or warning, would be a behaviour change. Say if you want it.
- The audit field itself comes in M1-19 and M4. This PR only makes `up.era` correct at the seam.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -count=1 ./... && golangci-lint run ./...
go test ./internal/proxy/ -run 'TestUpstreamEra|TestDiscoverProbe|TestRestartedStdio|TestEraMatrix|TestStdioUpstreamEras' -count=1 -v
make conformance   # run by hand here: every leg passed at both revisions, baselines unchanged, era_pairs 4/4
# mutation: change `if handshake {` to `if false && handshake {` in era.go; the new rows and the tier 1 test fail
```

`-race` did not run locally (no C compiler), so CI runs it.

## Decisions made without an ADR

- The era keys on the handshake. The version alone does not decide it. No exported type changed, and the spec 8.4 wording is updated in this PR.

## Questions for the receiver

- Should a stateful upstream that answers `initialize` with a version newer than the one requested be refused at startup (fail closed), rather than labelled?
