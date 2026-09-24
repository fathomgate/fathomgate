# T0.42, T0.43, T0.45 and the T0.44 doc part ready for review: the post-merge security review of T0.40 applied

- **Task:** T0.42 — Put the ADR 0014 refusal in the note slot, not the refused slot, so an upstream error is never replaced (S3). Also T0.43 (S1), T0.45 (S5, S7) and the documentation part of T0.44 (S2, S4)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer for T0.45)
- **State now:** in review (the board is not touched here: T0.39 is in flight in parallel and the orchestrator syncs `docs/milestones/M0.yaml`)
- **Branch / PR:** `fix/proxy-orphan-review` · https://github.com/joshscott13/netguard/pull/78
- **Date:** 2026-09-24

## Done

- **T0.42 (S3)**, `internal/proxy/input.go`: the ADR 0014 exception in `upstreamElicitation` now records its refusal with `p.refuseAsNote(u, s, ...)`, the note slot of the one call in flight, not its own slot. An upstream error for that call stays the upstream's; a completed result gets the refusal appended. This is not the reviewer's literal `p.refuse(u, nil, ...)`: that notes *every* call in flight at refuse time, and the text names `s.tool`, so a call that began since (possibly another session's) would get a note naming another session's tool. Test `TestOrphanRefusalNeverReplacesUpstreamError` (fails on the old line, checked). SECURITY.md's wrong-call row is now true, and says when a refusal *can* stand in for an upstream error (attributed prompt only). The existence-and-timing residual is stated in SECURITY.md, the threat model and 8.4.
- **T0.43 (S1)**, `internal/proxy/proxy.go`, `input.go`: `Proxy.Run` connects the session itself (the same wait/close as `mcp.Server.Run`), records it in `p.locals` under a short lock once Connect returns, and gives it a key of its own, `l1`, `l2`, ... per Run. `agentSessionKey` decides from what the session is: a Run session → its key; a session id → `s<id>`; anything else (per-request stateless session, nil session) → `""`, the shared entry. `p.limits` no longer matters. Test `TestLocalAgentOwnOrphanWithListener` (fails on the old keying, checked).
- **T0.45 S5**: the `agentSessionKey` comment is rewritten; the empty key is the shared entry, foreign to every call including its own.
- **T0.45 S7**, `internal/proxy/http.go`: fixed, not only documented. `beginPOST` counts a POST on a not-yet-registered session id in `h.early[{sid, principal}]`; `register` (called by `settleSession`) adds that count to the new `liveSession.active` under `h.mu`, so `arm` starts no idle clock under it, and the early POST's end calls `endPOST` on the session. Lock order is `h.mu` then `ls.mu`; nothing takes them the other way round. Test `TestPOSTBeforeRegistration`.
- **T0.44 doc part**: threat-model row "call that ended normally" residual rewritten (per-event bound, not steady state; the shared entry is not pruned, logged or principal-attributed; no false recourse); profile-schema 8.4 (keying paragraph, *Accepted for M0*) and 8.5 (*Orphan TTL*) corrected; SECURITY.md session-binding row gains the residual and T0.44 as the fix. The `orphanOverflow` code and `http_review_test.go` (the `IsZero` assertion after pruning) are **unchanged**.
- `CHANGELOG.md` Unreleased: Security (T0.42, T0.43, T0.44 doc) and Fixed (S7, S5).

### Fix round after approval (both reviewers, 2026-09-24)

- **Go 1, no lock across Connect**, `proxy.go`: `Run` puts a `ready` channel in `p.connecting` *before* `Connect`, records the session under a short `localMu` hold afterwards, then closes `ready`. `localKey(ctx, ss)` returns the recorded key. If the session is not recorded and a Run is connecting, it waits on that channel and looks again. If its ctx ends first it returns `""`, which fails closed into the shared entry. `agentSessionKey` now takes the request ctx. **This is not the transport wrapper that was suggested**, and here is why. go-sdk's stdio and in-memory connections implement the unexported `serverConnection.sessionUpdated`, which is what refuses JSON-RPC batches at 2025-06-18 and later. A wrapper from outside the package cannot implement it, so wrapping would silently drop that refusal on the wire. The guarantee is the same without it: no request on the new session is keyed before the record exists, and no lock is held across Connect. A new test, `TestLocalKeyDuringConnect`, is permanent. A test hook holds Run between Connect and the record while the agent initialises and calls. The test sees the handler waiting, then checks the call's orphan is `l1` with no shared entry. It fails when the wait is removed (I checked). It also checks the ctx-ends path gives `""`. The hooks are two nil func fields on `Proxy`.
- **Go 2**: a connect failure is `proxy: connect agent session: %w`.
- **Go 3**: both refusal log lines carry `attributed` (`refuse`: true when it has a call, false otherwise; `refuseAsNote`: false).
- **Go 4**: `liveSession.running` is set by `arm`, `startPOST`, `endPOST`, `stop` and `expire`, and `TestPOSTBeforeRegistration` reads it. That test's handler is built with a real proxy. `foreignOrphan` and `expireOrphan` use `p.now()`. The `localSessions` polling helper is gone: `TestAgentSessionKey` now drives two real Runs and reads their `l1` and `l2` orphans.
- **Go 6**: `Run`'s doc says a second Run is allowed and gets its own key, and that no lock is held across Connect, so a blocking Connect only delays requests waiting for a key.
- **Security N1**: fixed the listener comment in `TestAgentSessionKey`: the empty key is the shared entry, foreign to every call including its own.
- **Security L1**: S2 has its own threat-model row, "Cross-principal refusal of stateful prompts via the shared orphan entry", status **Open**, owner mcp-protocol-engineer, T0.44, blocks T0.31. Row 38 now accepts only the keyed-session residual. SECURITY.md's session-binding row and spec 8.4 say "Open (T0.44, must land before `--listen`)".
- **N2**: the CHANGELOG now says the upstream error "may quote (a go-sdk upstream does)" the ADR 0014 refusal.
- **N4**: SECURITY.md, the threat model and 8.4 now say that which refusal an agent sees reveals whether another session ended a call on that upstream within `OrphanTTL`, the same disclosure `errEndedElsewhere` makes.
- **Evidence**: added `TestLocalKeyDuringConnect` and `TestOrphanRefusalNeverReplacesUpstreamError` to row 37, and `TestPOSTBeforeRegistration` to the slow-agents / idle-expiry row.

### Second fix round (security re-review at 3666825, approved)

- **L1**, `input.go`: `agentSessionKey` now checks the session id first (`s<id>`), then the principal (a principal means the call came over the listener, including every stateless request, so it gets `""`). It asks `localKey` only when a call has neither. A listener call therefore never waits behind a connecting Run ahead of `l.admit`. New test `TestListenerCallNeverWaitsForRun`: with an entry that is never released in `p.connecting`, a 2025 and a 2026 listener call each finish at once. The wait hook never fires, the stateful call is keyed `s<id>` and the stateless one lands in the shared entry. It fails with the old lookup order (checked).
- **N1**, `proxy.go`: `Run` releases its `ready` entry through a `sync.Once` that runs right after the record and in a defer, so a recovered panic in `Connect` cannot leave the entry behind.
- **N2**: no doc now says listener calls wait. `Run`'s doc, the CHANGELOG, 8.4 and the threat-model evidence say that only a local request waits.
- **N3**: profile-schema 8.4 has its own **Open.** paragraph for the shared entry (T0.44, before `--listen`).
- `go test ./internal/proxy/ -count=5` passed (58 s) after this round; CI runs `-race` on the pushed head.

## Look at this first

1. **`TestProgressStuckAgent` and `TestEndBeforeFinish` (`progress_stall_test.go`) changed meaning.** They run two agents on one proxy through two `Run` calls. Before, both were keyed `local`, so agent B was shown a prompt although agent A's call had just ended on the same upstream: exactly the grouping the T0.40 handoff asked you to attack (question 1 there), and it was real in-process. They now first expect the orphan refusal (`refusedB`: not the "2 in flight" reason, so A's call did leave the in-flight set, which is what they pin), then age A's orphan and expect the prompt to reach B.
2. **Over the HTTP listener, a 2026-era agent against a 2025-era upstream now gets the upstream's JSON-RPC error**, which quotes netguard's ADR 0014 refusal, instead of netguard's tool error (`TestHTTPEraMatrix` updated). That is S3 working as intended: the per-request session's earlier call sits in the shared entry, so the exception path fires on nearly every such call. On stdio the prompt is attributed, so the tool error is unchanged, and `era_pairs` still reads `refused per ADR 0014`.
3. `Proxy.localKey` and `Run`'s `connecting` / `ready` handshake (fix round, Go 1). The marker is registered before `Connect`, and the record and the channel close happen after it. Only a local request (no session id, no principal) waits while a Run is connecting; since the second fix round a listener call never waits (below).

## Deliberately unfinished

- **T0.44 code** (bound, reap, log the shared entry; S2): needs the maintainer's choice of direction. The docs now say plainly that it is open.
- The board (`docs/milestones/M0.yaml`) is not edited here; `STATUS.md` is re-rendered only for this note.
- `-race` not run: no C toolchain on this Windows machine (`CGO_ENABLED=1` needs gcc). `internal/proxy` passed with `-count=5`; CI runs `-race`. One `-count=5` run, made while the conformance suite ran alongside, failed once in T0.39's `TestDiscoverProbeRestartsStdioUpstream` (stderr line not seen before its deadline, before any code this PR touches runs); it passed `-count=20` alone and `-count=5` again. Looks like a load-sensitive timing in that test, not this change; it is being fixed in the T0.39 review PR, and `connect_test.go` is left alone here. After the fix round, `go test ./internal/proxy/ -count=10` passed (115 s).
- `golangci-lint` not run locally (no pinned Windows binary, no `make`); CI runs `make lint`.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...
go test ./internal/proxy/ -count=10
go test ./internal/proxy/ -run 'TestOrphanRefusalNeverReplacesUpstreamError|TestLocalAgentOwnOrphanWithListener|TestLocalKeyDuringConnect|TestPOSTBeforeRegistration|TestAgentSessionKey|TestProgressStuckAgent|TestEndBeforeFinish|TestHTTPEraMatrix' -v
make policy-test && make fixtures-check && python tools/status/render.py --check
make conformance   # run here leg by leg (tests/conformance/run.sh <leg> <rev>) plus era_pairs.py: all green, no baseline change
```

## Decisions made without an ADR

- **`refuseAsNote` on the sole call, not `refuse(u, nil, ...)`** (reason above).
- **Every `Run` gets its own key** instead of refusing a second `Run`. A refusal broke the in-process two-agent tests, and per-Run keys are the safe reading of "one session, one key" without changing `Run`'s contract. `netguard serve` still calls Run once (ADR 0012). No exported identifier changed.
- **S7 fixed rather than documented**, with a new unexported map bounded by the POST caps.
- **A `connecting` marker instead of a transport wrapper** for Go 1 (reason in the fix-round section), plus two nil test-hook fields on `Proxy`.

## Questions for the receiver

1. Is the existence-and-timing residual of the note (the agent learns a prompt happened on that upstream around its call) acceptable as stated, or should an orphan-refused prompt produce no note at all?
2. ~~Is a second `Run` worth refusing?~~ Answered in the fix round: allowed, with its own key, and `Run`'s doc says so.
3. Is the `connecting` marker an acceptable substitute for the transport wrapper, given the batch-refusal regression the wrapper would cause?
