# T0.57 ready for review: evict a principal's idle session at the session cap; orphan rule kept

- **Task:** T0.57 — Stop the listener's session cap and orphan rule locking out an agent that restarts without ending its session
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review
- **Branch / PR:** `fix/session-cap-lockout` · see the PR that carries this note
- **Date:** 2026-09-25

## Done

- **Session cap, `internal/proxy/http.go` `reserveSession`.** When an `initialize` would pass the per-principal cap (4) or the overall cap (16), fathomgate first evicts the principal's own least recently used idle session. Idle means no POST in progress, no GET stream open, no call in flight (`callLimits.busy`, so a 2025 call whose POST was dropped counts) and not already stopped. The slot moves at once (`sessionSlot`, released exactly once). The evicted session's own principal gets 404 from fathomgate on POST and GET (`beginPOST`, `beginGET`), so nothing new starts on it while go-sdk closes it on a goroutine `callLimits.track` owns and `Proxy.Close` joins. Another principal's sessions are never candidates. With none idle the 503 stands, and a Warn line (at most one a second) gives `sessions posting streaming calling closing` for the principal. GETs are now counted per session, and a GET that arrives before registration is counted too (`earlyGets`, as T0.45's `early` counts POSTs).
- **Why eviction and not a shorter idle timeout:** eviction acts only when a slot is wanted, and never touches a session that is in use. A shorter timeout would close quiet live sessions for nothing, and would still refuse for its own length.
- **Orphan rule: unchanged, by decision.** A principal's new session does **not** inherit its earlier session's ended calls. Reasoning below.
- **SSE `retry:` field: recorded, not fixed.** go-sdk v1.8 writes `retry:` only in the close event of `RequestExtra.CloseSSEStream` (streamable.go `stream.close`), which asks the client to reconnect and resume from an event store. ADR 0016 gives the listener no event store, and 2026-07-28 deprecates resumption. Closing the agent's stream without one would lose the call's result. Run alone on a fresh fathomgate, `server-sse-polling` reports `server-sse-priming-event` (as both control legs do) and `server-sse-retry-field`.
- **Tests (`session_cap_test.go`):** `TestHTTPSessionCapEviction` has five cases: the least recently used session is evicted, and the others and the new one answer; a session with a dropped-POST call, one with a GET stream and one with a POST whose body is still arriving are all kept, the 503 is given, the call is not cancelled and the Warn line has the counts; another principal's idle sessions are not evicted; the overall cap evicts only the principal's own session; a real go-sdk client connects after the crashed agent's raw session is evicted. Also `TestEvictedSessionRefusedBeforeSDK` and `TestGETBeforeRegistration`. `TestHTTPSessionsPerPrincipal` now waits for the clients' GET streams. A mutation run killed all five rules (drop `busy`, drop `active`, drop `gets`, drop the principal filter, invert the least-recently-used order).
- **Docs:** ADR 0016 amendment (2026-09-25, T0.57), profile-schema 8.5 limit 8 and a new *Eviction* paragraph, 8.4 cross-session bullet, threat-model rows 34 and 41, conformance README and both 2025 baseline headers (comments only), CHANGELOG `Fixed`.

## Look at this first

- The orphan decision, then `reserveSession` / `idlestLocked` / `evictLocked` in `http.go`.
- **Orphan rule, why no inheritance.** The rule exists because a stateful upstream's `elicitation/create` names no call. After the old session's call ends, the upstream may still send a prompt for it (it ignored `notifications/cancelled`, or a background job, or a prompt go-sdk dispatched after the result). If the new session's call is the only one in flight and inherits the old session's orphans, that prompt goes to the new session's human as though it belonged to the current call. The human's `accept` then goes back upstream as the answer to the **abandoned** call. From M3 that could be an approval or a credential for an operation the human never saw. Grouping by principal does not remove this, because a principal is a token and not a conversation. The restarted agent is a new conversation, and several agents or people can share one token (8.4 *Accepted for M0* already says so). The spec also said so before this task: "a principal's own orphan blocks its other sessions as any other session's would". The cost is bounded and fails closed: the new session's stateful-upstream prompts are refused for at most `OrphanTTL` (5 minutes) after the old calls ended, and the Warn line names `ended_calls_of`. Tool calls are unaffected. No narrower safe inheritance exists: "the old session is gone" does not mean "the upstream stopped working on its call".
- **What is new for you to accept or reject.** Anyone holding a principal's token can now end that principal's idle sessions by opening new ones, without knowing their ids. Before, the same holder could only fill the principal's slots and lock its other clients out. Across principals nothing changes. It is recorded in 8.5 *Eviction* and row 34.

## Deliberately unfinished

- **The conformance 503s stay.** When a scenario throws, the suite leaves its client's standalone GET stream open. `chain.log` shows `sessions=4 posting=0 streaming=4 calling=0`. Those sessions look exactly like four live, quiet agents, so evicting them would also evict live agents. No baseline entry changed. The fix is the upstream suite request already drafted in the T0.32 handoff (terminate the session on every exit path).
- Not done: evicting a session that has a GET stream open, or an extra age-based rule for it. That is a question for the maintainer, below.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
go test -count=20 -run 'TestHTTPSessionCapEviction|TestEvicted|TestGETBefore|TestHTTPSessionsPerPrincipal' ./internal/proxy/
make conformance   # 2025 legs: the 503s remain, with the new Warn line in results/*/chain.log
```

## Decisions made without an ADR

- The orphan non-inheritance and the SSE `retry:` record went into an ADR 0016 amendment, not a new ADR, because neither changes a decision. Eviction changes step 7's behaviour but no export and no `HTTPOptions` field.
- The least recently used session is chosen by when it was registered or its last POST or GET ended, rather than by creation time: a crashed agent's session is the one used longest ago.
- There is no minimum idle age, so a session can be evicted a moment after it was used. A principal that really runs more than 4 quiet clients without GET streams therefore rotates them: each evicted client gets a 404 and re-initialises.

## Questions for the receiver

1. Do you accept the new same-principal capability (ending a principal's idle sessions without their ids)?
2. Should a session with an open GET stream but no POST for a long time (for example `OrphanTTL`) also be evictable? It would clear the conformance 503s, at the risk of evicting a live agent that is only quiet.
