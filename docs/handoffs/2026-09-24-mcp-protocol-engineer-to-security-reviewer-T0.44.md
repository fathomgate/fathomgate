# T0.44 code part ready for review: a key per stateless request, a per-principal orphan quota, and the principals behind each refusal in the log

- **Task:** T0.44: Bound, reap and log the shared orphan entry so cross-principal refusal is neither indefinite nor silent (S2, S4)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review, first fix round applied (see *Fix round*). `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `fix/proxy-orphan-per-request-key` · https://github.com/joshscott13/netguard/pull/82
- **Date:** 2026-09-24

## Done

- **Maintainer decision (2026-09-24), `internal/proxy/input.go`:** `agentSessionKey` no longer returns `""`. A call netguard cannot name to a session gets `requestKey()`, which is `r` plus a per-proxy `atomic.Uint64` (`Proxy.requestKeys`). That covers a 2026-era per-request session over the listener, a call with no session, and a local call whose ctx ended while it waited for `Run`. The key can collide with neither `s<id>` nor `l<n>`. Its orphan is an ordinary table entry: pruned at `OrphanTTL`, and logged at Info with its principal when reaped. `upstream.orphanOverflow` is gone.
- **Table-full design (accepted by the maintainer, 2026-09-24):** the 1024-entry global cap is replaced by `maxOrphansPerPrincipal = 256` keyed records per principal per upstream (`upstream.orphansOf` counts them). Past the quota, that principal's further ended calls fold into `upstream.overflow[principal]`, one record holding the latest expiry and a call count. Its properties:
  - It fails closed: the record is foreign to every call, that principal's own sessions included.
  - It is logged at Warn once, when made (`endCall`), and at Info when reaped, with `calls=<n>`.
  - It cannot displace another principal's records.
- **S4, the log:** when the orphan rule refuses a prompt, netguard logs the sorted principals whose live ended calls caused the refusal (first as `blocked_by`, renamed `ended_calls_of` in the fix round, which also moved it onto the refusal line itself). The local agent appears as `(local)`, which `validPrincipalName` rejects, so it cannot be confused with a real principal. The texts the agent and the upstream see are unchanged and name no principal.
- `forward`'s defer now calls `p.endCall`, which runs `end`, `logReaped` and the quota warning. `end` returns `(reaped, overflowed)`.
- **Tests (`orphan_quota_test.go`, new):**
  - `TestHTTPStatelessOrphanPerRequest`: alice (2026) and bob (2025) over the listener, with a test clock installed before the handler serves (new `httpSetup.now`). Bob's prompt is refused while alice's per-request orphans are live, and the log shows `ended_calls_of=[alice]`. After `OrphanTTL`, both of alice's records are reaped and logged with `principal=alice`, and bob's prompt is relayed.
  - `TestOrphanQuotaPerPrincipal`, `TestOrphanQuotaLogged`, `TestEndedCallsOfNamesLocalAgent` (renamed in the fix round).
- **Changed tests:**
  - `TestOrphanAttribution`: the old `orphanOverflow.IsZero()` check after pruning now asserts that the overflow record *is* reaped, with principal and count.
  - `TestAgentSessionKey`: fresh `r` keys, never repeated.
  - `TestLocalKeyDuringConnect`: a ctx-ended wait yields an `r` key.
  - `TestListenerCallNeverWaitsForRun`: the stateless call leaves one `r` entry for alice.
  - `TestLocalAgentOwnOrphanWithListener` and `abandonCall` updated to match.
- **Docs:**
  - Threat model: the shared-entry row now reads Accepted (residual), maintainer, 2026-09-24 (fix round), and the two rows above it are adjusted.
  - SECURITY.md session-binding row.
  - profile-schema 8.4 (keying paragraph; **Open** replaced by the accepted residual) and 8.5 *Orphan TTL*.
  - CHANGELOG Unreleased, Security section. ADR 0014's ordering is untouched.

## Look at this first

1. `upstream.end` and `attribute` in `input.go`. The argument that the per-principal quota is safe: an overflow record blocks other principals exactly as long as the keyed records it replaces would have. So an overflow gives a principal no reach over others that its ordinary ended calls lack. Its only extra cost falls on its own sessions.
2. **Why not the literal "over quota only blocks its own calls":** that would fail open. An upstream prompt names no call. If alice's over-quota ended call did not block bob, then a prompt for that call, arriving while bob's call is the only one in flight, would go to bob's human. Any live ended call from another session has to block.
3. **The residual, accepted by the maintainer (2026-09-24):** any principal that can call a stateful upstream can keep every other session's prompts on it refused, by ending one call per `OrphanTTL` or by holding one call open. This is inherent in attributing a prompt that names no call, and it fails closed. The log names the principal (`ended_calls_of`, `in_flight_of`). The only recourse is removing that token (a restart in M0); shortening `OrphanTTL` would give up the confused-deputy protection. M3 carries a new Open row: a per-upstream prompt policy, or binding a prompting stateful upstream to one principal.

## Deliberately unfinished

- The board YAML is not edited. `STATUS.md` is re-rendered only for this note.
- `-race` was not run locally (no gcc on this Windows machine). CI runs it.
- Setting the per-principal quota to 256 (not 1024) is a judgement call. The table now holds at most 257 × (principals + 1) records per upstream, and `pruneOrphans` scans all of them on every call end. Each record costs a principal nothing it could have received, so a smaller quota costs only log granularity.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && go test ./internal/proxy/ -count=5
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0 run ./...
go test ./internal/proxy/ -run 'TestHTTPStatelessOrphanPerRequest|TestOrphanQuota|TestOrphanModel|TestEndedCallsOf|TestUnattributedRefusalLog|TestRefusalLimiterBounded|TestStatelessSessionHasNoID|TestOrphanAttribution|TestAgentSessionKey|TestLocalKeyDuringConnect|TestListenerCallNeverWaitsForRun|TestHTTPAbandonedCallPrompt|TestHTTPEraMatrix' -v
make policy-test && make fixtures-check && python tools/status/render.py --check
make conformance   # here: tests/conformance/run.sh <leg> <rev> for all 8 leg/rev pairs, plus era_pairs.py; all baselines pass, no baseline change
```

## Decisions made without an ADR

- The table-full design (per-principal quota and per-principal overflow record) and the residual were accepted by the maintainer on 2026-09-24, with one orphan entry per stateless request kept. No exported identifier changed. The `(local)` label appears only in the `ended_calls_of` and `in_flight_of` log attributes.

## Fix round (reviews of PR #82: security and Go; maintainer decisions of 2026-09-24)

Maintainer decisions: (a) the per-principal quota design and the residual are accepted. The status now reads "Accepted (residual), maintainer, 2026-09-24" in the threat model, SECURITY.md and profile-schema 8.4, and a new threat-model row for M3 is Open (owner mcp-protocol-engineer): a per-upstream prompt policy, or binding a prompting stateful upstream to one principal. The ADR 0016 amendment table gains a row. (b) One orphan entry per stateless request stays; only the expected quota Warn is documented.

1. **L1 / Go should-fix 1:** the separate Warn line is gone. `refuseUnattributed` logs one line per refusal, and the principals are an attribute of that line only when the error is `errEndedElsewhere`. The ADR 0014 path (`refuseAsNote`) names the one call's principal as `in_flight_of` and never names ended calls. `TestHTTPStatelessOrphanPerRequest` now checks alice's own ADR 0014 refusal logs `in_flight_of=[alice]` and no `ended_calls_of`.
2. **Go nit 5, vocabulary:** `blocked_by` is now `ended_calls_of` (field `endedCallsOf`) everywhere.
3. **L2:** a prompt refused with more (or fewer) than one call in flight logs `in_flight_of`, the principals of those calls (`TestUnattributedRefusalLog`).
4. **L4:** unattributed refusal Warns go through `refusalLimiter`: one line per 10 s per (server, class of refusal, principal set), carrying `suppressed`, the number of lines held back since the last. At most 1024 keys; making room drops only stale keys, or all of them, so a line can only appear early, never be hidden. What is left: a burst's count is reported only with the next line for the same key. Tests: `TestUnattributedRefusalLog`, `TestRefusalLimiterBounded`.
5. **N1:** `agentSessionKey` uses `s<id>` only when `!c.agent.stateless()`. `TestStatelessSessionHasNoID` pins that go-sdk's stateless handler gives a `tools/call` session `ID()==""`, through a receiving middleware on the proxy's server. The `!stateless()` branch itself cannot be tested: a stateless session with an id cannot be built from outside go-sdk.
6. **Go should-fix 2:** the own-session check in `TestOrphanQuotaPerPrincipal` now asserts the exact set `[alice bob]`. With the mutant (`principal != f.principal` on the overflow loop in `attribute`) it fails with `["bob"]` (checked, then reverted).
7. **Reference model:** `TestOrphanModelNeverFailsOpen`, adapted from the security reviewer's test. The oracle drops expired entries, so each step is bounded. It runs 16 seeds × 3000 steps in about 0.2 s. The exact-set check became containment both ways, plus one allowed divergence: netguard may refuse where the oracle would not only through a live overflow record of the caller's principal. It also fails if seed 1 never overflows.
8. **Go nits:**
   - The upstream field comment states the 257 × (principals + 1) bound and that maps do not shrink.
   - The quota Warn now reads "until none has ended for the orphan TTL".
   - The `end` godoc is fixed, and so is the `now` field comment.
9. and 10. **M1, M2:** status per decision (a). Token removal is the only recourse; the TTL text says what a shorter one gives up.
11. **L2 in docs:** the hold-a-call-open variant is in the threat model's rows 38 and 39, 8.4, SECURITY.md and the CHANGELOG.
12. **L3:** the quota Warn is documented as expected above about 0.85 calls/s per principal per upstream (256 per 5 minutes). It applies to any upstream, not only a stateful one: every upstream records orphans.

CI: GitHub-hosted minutes are exhausted and PR #83 (self-hosted runners) is not merged, so CI is pending. The local gate is green; the numbers are in the PR comment.

## Questions for the receiver

1. ~~Residual acceptable?~~ Accepted by the maintainer, 2026-09-24.
2. ~~Rate-limit the refusal log?~~ Done in the fix round (L4). Is 10 s the right interval?
3. Is 256 the right per-principal quota, given the quota Warn fires above about 0.85 calls/s from one 2026-era agent?
