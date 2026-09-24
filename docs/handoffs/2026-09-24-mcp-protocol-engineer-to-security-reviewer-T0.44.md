# T0.44 code part ready for review: a key per stateless request, a per-principal orphan quota, and `blocked_by` in the log

- **Task:** T0.44: Bound, reap and log the shared orphan entry so cross-principal refusal is neither indefinite nor silent (S2, S4)
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `fix/proxy-orphan-per-request-key` · https://github.com/joshscott13/netguard/pull/82
- **Date:** 2026-09-24

## Done

- **Maintainer decision (2026-09-24), `internal/proxy/input.go`:** `agentSessionKey` no longer returns `""`. A call netguard cannot name to a session gets `requestKey()`, which is `r` plus a per-proxy `atomic.Uint64` (`Proxy.requestKeys`). That covers a 2026-era per-request session over the listener, a call with no session, and a local call whose ctx ended while it waited for `Run`. The key can collide with neither `s<id>` nor `l<n>`. Its orphan is an ordinary table entry: pruned at `OrphanTTL`, and logged at Info with its principal when reaped. `upstream.orphanOverflow` is gone.
- **Table-full proposal (for the maintainer to accept):** the 1024-entry global cap is replaced by `maxOrphansPerPrincipal = 256` keyed records per principal per upstream (`upstream.orphansOf` counts them). Past the quota, that principal's further ended calls fold into `upstream.overflow[principal]`, one record holding the latest expiry and a call count. Its properties:
  - It fails closed: the record is foreign to every call, that principal's own sessions included.
  - It is logged at Warn once, when made (`endCall`), and at Info when reaped, with `calls=<n>`.
  - It cannot displace another principal's records.
- **S4, the log:** when the orphan rule refuses a prompt, `upstreamElicitation` logs at Warn with `blocked_by=[...]`, the sorted principals whose live ended calls caused the refusal. The local agent appears as `(local)`, which `validPrincipalName` rejects, so it cannot be confused with a real principal. The texts the agent and the upstream see are unchanged and name no principal.
- `forward`'s defer now calls `p.endCall`, which runs `end`, `logReaped` and the quota warning. `end` returns `(reaped, overflowed)`.
- **Tests (`orphan_quota_test.go`, new):**
  - `TestHTTPStatelessOrphanPerRequest`: alice (2026) and bob (2025) over the listener, with a test clock installed before the handler serves (new `httpSetup.now`). Bob's prompt is refused while alice's per-request orphans are live, and the log shows `blocked_by=[alice]`. After `OrphanTTL`, both of alice's records are reaped and logged with `principal=alice`, and bob's prompt is relayed.
  - `TestOrphanQuotaPerPrincipal`, `TestOrphanQuotaLogged`, `TestBlockedByNamesLocalAgent`.
- **Changed tests:**
  - `TestOrphanAttribution`: the old `orphanOverflow.IsZero()` check after pruning now asserts that the overflow record *is* reaped, with principal and count.
  - `TestAgentSessionKey`: fresh `r` keys, never repeated.
  - `TestLocalKeyDuringConnect`: a ctx-ended wait yields an `r` key.
  - `TestListenerCallNeverWaitsForRun`: the stateless call leaves one `r` entry for alice.
  - `TestLocalAgentOwnOrphanWithListener` and `abandonCall` updated to match.
- **Docs:**
  - Threat model: the shared-entry row is now Mitigated (T0.44) and states the residual as *proposed*. The two rows above it are adjusted.
  - SECURITY.md session-binding row.
  - profile-schema 8.4 (keying paragraph; **Open** replaced by **Proposed for acceptance**) and 8.5 *Orphan TTL*.
  - CHANGELOG Unreleased, Security section. ADR 0014's ordering is untouched.

## Look at this first

1. `upstream.end` and `attribute` in `input.go`. The argument that the per-principal quota is safe: an overflow record blocks other principals exactly as long as the keyed records it replaces would have. So an overflow gives a principal no reach over others that its ordinary ended calls lack. Its only extra cost falls on its own sessions.
2. **Why not the literal "over quota only blocks its own calls":** that would fail open. An upstream prompt names no call. If alice's over-quota ended call did not block bob, then a prompt for that call, arriving while bob's call is the only one in flight, would go to bob's human. Any live ended call from another session has to block.
3. **The residual (proposed, not accepted):** any principal that can call a stateful upstream can keep every other session's prompts on it refused, by ending one call per `OrphanTTL`. This is inherent in attributing a prompt that names no call, and it fails closed. The row above already accepts it for keyed sessions; it is now uniform across all calls, and the log explains it. The recourse is `blocked_by`, then removing that token (a restart in M0; there is no live revocation) or shortening `OrphanTTL`. The maintainer decides whether this still blocks T0.31.

## Deliberately unfinished

- The board YAML is not edited. `STATUS.md` is re-rendered only for this note.
- `-race` was not run locally (no gcc on this Windows machine). CI runs it.
- Setting the per-principal quota to 256 (not 1024) is a judgement call. The table now holds at most 257 × (principals + 1) records per upstream, and `pruneOrphans` scans all of them on every call end. Each record costs a principal nothing it could have received, so a smaller quota costs only log granularity.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && go test ./internal/proxy/ -count=5
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0 run ./...
go test ./internal/proxy/ -run 'TestHTTPStatelessOrphanPerRequest|TestOrphanQuota|TestBlockedBy|TestOrphanAttribution|TestAgentSessionKey|TestLocalKeyDuringConnect|TestListenerCallNeverWaitsForRun|TestHTTPAbandonedCallPrompt|TestHTTPEraMatrix' -v
make policy-test && make fixtures-check && python tools/status/render.py --check
make conformance   # here: tests/conformance/run.sh <leg> <rev> for all 8 leg/rev pairs, plus era_pairs.py; all baselines pass, no baseline change
```

## Decisions made without an ADR

- The table-full design (per-principal quota and per-principal overflow record) is a proposal. No exported identifier changed. The `(local)` label appears only in `blocked_by`.
- `blocked_by` is a new Warn log line, and it fires on the ADR 0014 exception path too (for example, a 2026 agent against a 2025 upstream).

## Questions for the receiver

1. Is the residual acceptable as worded (threat model and 8.4 **Proposed for acceptance**), or should `OrphanTTL`'s 5-minute default drop before `--listen`?
2. Should `blocked_by` be rate-limited? A busy upstream prompting against a live foreign orphan logs one line per prompt.
3. Is 256 the right per-principal quota?
