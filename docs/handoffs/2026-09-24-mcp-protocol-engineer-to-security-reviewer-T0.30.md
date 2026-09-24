# T0.30 ready for review: `ng3.` requestState bound to transport and principal, transport on `call`, progress relay owned by one request, attribution rule in 8.4

- **Task:** T0.30: Bind the sealed requestState to the principal (ng3.), carry transport and principal on call, state the cross-session attribution rule in 8.4
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here (board PR #84 is open); the orchestrator syncs the board.
- **Branch / PR:** `feat/proxy-principal-binding` · https://github.com/joshscott13/netguard/pull/85
- **Date:** 2026-09-24

## Done

- **`internal/proxy/state.go`: the `ng3.` envelope.**
  - `statePrefix` is now `ng3.`.
  - `stateBinding{transport, principal}` and its `aad()`: the prefix, then the transport and then the principal, each followed by a NUL byte. The encoding is unambiguous because the transport is one of two constants and principal names are `[A-Za-z0-9_.:-]`.
  - `seal(st, b)` and `open(state, b)` use that as the AES-GCM additional data. The binding is authenticated but not stored, so a state presented under another binding fails `aead.Open` and returns `errStateAuth` before anything is decrypted.
  - Key handling is unchanged: 32 random bytes per process, a random 96-bit nonce, and the 96 KiB cap shared by `seal` and `open`.
- **The decision on `ng2.`.** `retiredStatePrefixes = {"ng1.", "ng2."}` maps to the new `errStateRetired`: `requestState was issued by an earlier netguard process; call the tool again without it`.
  - No such state could ever verify, because the key is per process and an upgrade is a restart. This changes only the text the agent reads, which used to be "not issued by netguard" and now says what to do.
  - Nothing migrates, as ADR 0016 says.
- **`internal/proxy/proxy.go` and `http.go`: transport on the call.**
  - `call.transport` (`transportStdio` / `transportHTTP`) sits beside `call.principal`, and `call.binding()` returns both.
  - `transportOf(req)` returns http when go-sdk's `RequestExtra` has `Header` (set by the Streamable HTTP server on every request) or `TokenInfo`, and stdio otherwise. So stdio means "a session `Proxy.Run` serves"; tests pass an in-memory transport there.
  - `forward` seals with `c.binding()`, and `resume` opens with it.
- **`internal/proxy/input.go`: `warnState`.** Each refused `requestState` is logged at Warn with the server, the tool, the presenting `transport` and `principal`, and the netguard-side reason.
  - The line never names the issuer, which netguard cannot know for `errStateAuth` anyway.
  - It is rate-limited through `refusalLog`, keyed by server, transport, principal and reason, with `suppressed` and `suppressed_lost` counts.
- **`internal/proxy/progress.go`: the relay owns one request.**
  - `newProgressRelay(ctx, c call, …)` records `sessionKey`, `transport` and `principal`.
  - `watchProgress` redraws the token if it is already mapped. It never shares or replaces a mapping.
  - `unwatchProgress` deletes only its own mapping.
- **Docs.**
  - ADR 0016: a dated amendment row. It records that the binding covers the transport as well as the principal, that another binding's retry gets the forgery's detail, the `ng2.` handling, the progress owner, and that nothing is exported.
  - profile-schema 8.2 (error row) and 8.4: the envelope paragraph, Progress, the new *The cross-session attribution rule (T0.30)*, and *Accepted for M0*. Also era detection (transport and principal travel to `Proxy.dispatch`) and the 8.5 principal text.
  - SECURITY.md: the forged-retry, replay and session-binding rows. The envelope is now listed as closed.
  - Threat model: a new row, "Cross-principal `requestState` replay" (MCP07/MCP03, Mitigated), plus progress-token-scope evidence and the OWASP mapping.
  - CHANGELOG Unreleased, Security; `internal/proxy/doc.go`.
- **Tests (`internal/proxy/principal_test.go`, new).** `TestSealerBinding`, `TestHTTPRequestStateBoundToPrincipal` (cross-principal, `ng2.`, no leak in message, data or log), `TestRequestStateBoundToTransport` (both directions on one proxy), `TestCallCarriesTransportAndPrincipal`, `TestProgressRelayPerSession` (three sessions, one agent token), `TestWatchProgressNeverSharesToken`. `state_test.go` adapted: `ng1.` and `ng2.` expect `errStateRetired`.

## Look at this first

1. `stateBinding.aad` and `sealer.open` in `state.go`. Is additional data the right place for the binding, rather than plaintext fields compared after decryption? I chose it for two reasons: the check cannot be left out by a later edit of `resume`, and a cross-principal presenter learns nothing, not even whether the state expired or which tool it was for. The cost is that the log cannot say whose state it was.
2. `transportOf` in `http.go`. It relies on go-sdk v1.8 setting `RequestExtra.Header` on every Streamable HTTP request (both handlers). If a go-sdk bump stopped doing that, an HTTP call would read as stdio. The principal would still differ, because the listener always authenticates a non-empty one, so the envelope binding would still refuse. `TestCallCarriesTransportAndPrincipal` pins the behaviour for both eras.
3. The attribution rule in profile-schema 8.4. It says principal and transport are never part of the orphan key and never widen it. Check that this matches `agentSessionKey` and `attribute` as T0.44 left them. I changed no attribution code.

## Deliberately unfinished

- **The envelope binds no session.** A stateless request has none, and a stateful agent never receives a `requestState`. So two clients that share one token can replay each other's states within 30 minutes. This is accepted, and stated in 8.4 and SECURITY.md.
- **Single-use `requestState` ids** stay M3 (ADR 0014, option B requirement 1).
- **Progress.** The upstream token is still the only lookup key, since the upstream names nothing else. "Per session" is therefore met by a fresh token per request plus the owner fields, not by a second map level. A hostile upstream can still swap progress between its own calls, across sessions included. That residual was already accepted in ADR 0016 and is unchanged.
- **`-race`** was not run locally (no cgo toolchain on this Windows machine). CI runs it on the WSL runners.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && gofmt -l .
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0 run ./...
make policy-test && make fixtures-check && python tools/status/render.py --check
go test ./internal/proxy/ -run 'TestSealerBinding|TestHTTPRequestStateBoundToPrincipal|TestRequestStateBoundToTransport|TestCallCarriesTransportAndPrincipal|TestProgressRelayPerSession|TestWatchProgressNeverSharesToken|TestSealer|TestMRTRWire|TestHTTPEraMatrix' -v
go test ./internal/proxy/ -run TestProgressRelayPerSession -count=30
make conformance   # here: tests/conformance/run.sh <leg> <rev> for all 8 pairs, plus era_pairs.py; all baselines pass, no baseline change
```

## Decisions made without an ADR

These are recorded as an ADR 0016 amendment row, following the precedent of its existing rows. No exported identifier changed.

- The transport is bound as well as the principal.
- A cross-binding retry gets the forgery's detail.
- `ng2.` gets its own detail.
- The Warn line for refused states.

## Questions for the receiver

1. Should a cross-principal retry be told apart from a forgery in the log? That would mean plaintext binding fields compared after decryption, trading the "learns nothing" property for operator attribution of the issuer.
2. Is a distinct detail for `ng1.`/`ng2.` acceptable? Anyone can write that prefix, so it tells the agent "call again", not that the state was genuine.
