# T0.42, T0.43, T0.45 and the T0.44 doc part ready for review: the post-merge security review of T0.40 applied

- **Task:** T0.42 — Put the ADR 0014 refusal in the note slot, not the refused slot, so an upstream error is never replaced (S3). Also T0.43 (S1), T0.45 (S5, S7) and the documentation part of T0.44 (S2, S4)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer for T0.45)
- **State now:** in review (the board is not touched here: T0.39 is in flight in parallel and the orchestrator syncs `docs/milestones/M0.yaml`)
- **Branch / PR:** `fix/proxy-orphan-review` · PR link in the PR description (opened after this note)
- **Date:** 2026-09-24

## Done

- **T0.42 (S3)**, `internal/proxy/input.go`: the ADR 0014 exception in `upstreamElicitation` now records its refusal with `p.refuseAsNote(u, s, ...)`, the note slot of the one call in flight, not its own slot. An upstream error for that call stays the upstream's; a completed result gets the refusal appended. This is not the reviewer's literal `p.refuse(u, nil, ...)`: that notes *every* call in flight at refuse time, and the text names `s.tool`, so a call that began since (possibly another session's) would get a note naming another session's tool. Test `TestOrphanRefusalNeverReplacesUpstreamError` (fails on the old line, checked). SECURITY.md's wrong-call row is now true, and says when a refusal *can* stand in for an upstream error (attributed prompt only). The existence-and-timing residual is stated in SECURITY.md, the threat model and 8.4.
- **T0.43 (S1)**, `internal/proxy/proxy.go`, `input.go`: `Proxy.Run` connects the session itself (the same wait/close as `mcp.Server.Run`), records it in `p.locals` under `localMu` held across the connect, and gives it a key of its own, `l1`, `l2`, ... per Run. `agentSessionKey` decides from what the session is: a Run session → its key; a session id → `s<id>`; anything else (per-request stateless session, nil session) → `""`, the shared entry. `p.limits` no longer matters. Test `TestLocalAgentOwnOrphanWithListener` (fails on the old keying, checked).
- **T0.45 S5**: the `agentSessionKey` comment is rewritten; the empty key is the shared entry, foreign to every call including its own.
- **T0.45 S7**, `internal/proxy/http.go`: fixed, not only documented. `beginPOST` counts a POST on a not-yet-registered session id in `h.early[{sid, principal}]`; `register` (called by `settleSession`) adds that count to the new `liveSession.active` under `h.mu`, so `arm` starts no idle clock under it, and the early POST's end calls `endPOST` on the session. Lock order is `h.mu` then `ls.mu`; nothing takes them the other way round. Test `TestPOSTBeforeRegistration`.
- **T0.44 doc part**: threat-model row "call that ended normally" residual rewritten (per-event bound, not steady state; the shared entry is not pruned, logged or principal-attributed; no false recourse); profile-schema 8.4 (keying paragraph, *Accepted for M0*) and 8.5 (*Orphan TTL*) corrected; SECURITY.md session-binding row gains the residual and T0.44 as the fix. The `orphanOverflow` code and `http_review_test.go` (the `IsZero` assertion after pruning) are **unchanged**.
- `CHANGELOG.md` Unreleased: Security (T0.42, T0.43, T0.44 doc) and Fixed (S7, S5).

## Look at this first

1. **`TestProgressStuckAgent` and `TestEndBeforeFinish` (`progress_stall_test.go`) changed meaning.** They run two agents on one proxy through two `Run` calls. Before, both were keyed `local`, so agent B was shown a prompt although agent A's call had just ended on the same upstream: exactly the grouping the T0.40 handoff asked you to attack (question 1 there), and it was real in-process. They now first expect the orphan refusal (`refusedB`: not the "2 in flight" reason, so A's call did leave the in-flight set, which is what they pin), then age A's orphan and expect the prompt to reach B.
2. **Over the HTTP listener, a 2026-era agent against a 2025-era upstream now gets the upstream's JSON-RPC error**, which quotes netguard's ADR 0014 refusal, instead of netguard's tool error (`TestHTTPEraMatrix` updated). That is S3 working as intended: the per-request session's earlier call sits in the shared entry, so the exception path fires on nearly every such call. On stdio the prompt is attributed, so the tool error is unchanged, and `era_pairs` still reads `refused per ADR 0014`.
3. `Proxy.localKey` and the `localMu` hold across `server.Connect` in `Run`: check that no request on the new session can be keyed before `p.locals` has its entry, and that holding the write lock across the connect cannot deadlock (go-sdk's `connect` returns without waiting for any handler).

## Deliberately unfinished

- **T0.44 code** (bound, reap, log the shared entry; S2): needs the maintainer's choice of direction. The docs now say plainly that it is open.
- The board (`docs/milestones/M0.yaml`) is not edited here; `STATUS.md` is re-rendered only for this note.
- `-race` not run: no C toolchain on this Windows machine (`CGO_ENABLED=1` needs gcc). `internal/proxy` passed with `-count=5`; CI runs `-race`.
- `golangci-lint` not run locally (no pinned Windows binary, no `make`); CI runs `make lint`.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...
go test ./internal/proxy/ -count=5
go test ./internal/proxy/ -run 'TestOrphanRefusalNeverReplacesUpstreamError|TestLocalAgentOwnOrphanWithListener|TestPOSTBeforeRegistration|TestAgentSessionKey|TestProgressStuckAgent|TestEndBeforeFinish|TestHTTPEraMatrix' -v
make policy-test && make fixtures-check && python tools/status/render.py --check
make conformance   # run here leg by leg (tests/conformance/run.sh <leg> <rev>) plus era_pairs.py: all green, no baseline change
```

## Decisions made without an ADR

- **`refuseAsNote` on the sole call, not `refuse(u, nil, ...)`** (reason above).
- **Every `Run` gets its own key** instead of refusing a second `Run`. A refusal broke the in-process two-agent tests, and per-Run keys are the safe reading of "one session, one key" without changing `Run`'s contract. `netguard serve` still calls Run once (ADR 0012). No exported identifier changed.
- **S7 fixed rather than documented**, with a new unexported map bounded by the POST caps.

## Questions for the receiver

1. Is the existence-and-timing residual of the note (the agent learns a prompt happened on that upstream around its call) acceptable as stated, or should an orphan-refused prompt produce no note at all?
2. Is a second `Run` on one proxy worth refusing in production code paths (it cannot happen from `netguard serve`), given the in-process tests rely on it?
