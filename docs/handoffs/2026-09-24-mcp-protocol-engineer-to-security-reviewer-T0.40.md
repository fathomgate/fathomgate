# T0.40 ready for re-review: an upstream prompt for a call that ended normally no longer reaches another session's human

- **Task:** T0.40 — Apply the PR #72 re-review findings (prompts after a finished call, idle-timer gaps, orphan TTL and memory, ADR 0016 principal text)
- **From → To:** mcp-protocol-engineer → security-reviewer
- **State now:** in review
- **Branch / PR:** `fix/proxy-http-rereview` · https://github.com/joshscott13/netguard/pull/75
- **Date:** 2026-09-24

## Done

- `internal/proxy/input.go`, `proxy.go` (J1): **every** call that ends is recorded as an orphan of its agent session, not only a cancelled one, in the same critical section that removes it from the upstream's in-flight set. A stateful upstream that answered a call and kept working, or whose prompt go-sdk dispatched after the result, can no longer have that prompt attributed to another session's call.
- `internal/proxy/input.go` (J5, K2): orphans are keyed by netguard's own key for the agent session (`Proxy.agentSessionKey`), never by `*mcp.ServerSession`. A per-request session of the stateless era gets the empty key and goes to the shared bucket, which is foreign to every later call and costs no table entry. Expired orphans are pruned in `end()` and returned so the caller logs them.
- `internal/proxy/http.go`, `calls.go` (J3): `HTTPOptions.OrphanTTL`, default **5 minutes**, separate from the 30-minute `SessionTimeout` it used to borrow. Reaping an orphan logs at Info with the server and the principal it was blocking for.
- `internal/proxy/http.go` (J2, K3, K4): a session-less POST's response header registers the session whatever its initialise state; the `liveSession` godoc says why the idle clock is real-time; `proxy.ErrMCPGODEBUG` is the one refusal text, returned by `cmd/netguard`'s pre-flight check too.
- Docs in the same PR: profile-schema 8.4 and 8.5, ADR 0016 amendments (J6 principal text, the TTL, the export), the threat-model row and its accepted residual, SECURITY.md's session-binding row, `CHANGELOG.md`.
- Tests: `TestHTTPPromptAfterFinishedCall` (the J1 proof of concept), `TestAgentSessionKey`, `TestOrphanTTLSeparateFromIdle`, `TestOrphanReapedLogsPrincipal`, `TestHTTPSessionRegisteredFromResponseHeader`, plus a rewritten `TestOrphanAttribution`.

## Look at this first

1. **`Proxy.agentSessionKey` in `internal/proxy/input.go`.** Everything J1 protects rests on it: two different agent sessions must never share a key, or one session's prompt can reach the other's human. Over the listener a session with an id is keyed by that id; one without is treated as a per-request stateless session and given the empty key (never matched, always foreign); everything else is the single local stdio agent. Attack the third case: is there any way to get two distinct agent sessions on one proxy with no HTTP listener and no session id, and does `localAgentKey` then group them?
2. **The ADR 0014 exception in `upstreamElicitation`.** When the orphan rule refuses the one call in flight and that call's agent could not have been shown any prompt anyway, netguard refuses with the ADR 0014 text and records the refusal against that call (`p.refuse(u, s, ...)`) rather than as an unattributed note. No prompt crosses to a human on either path, but the refusal is now attached to a call that may not be the one the upstream meant. Check that this cannot put a wrong reason in place of an upstream error in a way that misleads an agent, and that the text still names no upstream value.

## Deliberately unfinished

- **J4 (the 5-second shutdown grace) is not here.** It stays in T0.31, as the brief says.
- The board entry for T0.40 is not touched: it lands with the open board-sync PR #73 (`chore/m0-board-sync-8`). `STATUS.md` is therefore unchanged and `render.py --check` is clean.
- `-race` was not run: this machine has no C toolchain (`CGO_ENABLED=1` fails, "gcc not found"). CI covers it. `internal/proxy` was run with `-count=5` and the `goleak` check passes.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./internal/... ./cmd/...
bin/netguard policy test $(find policies -name '*.test.yaml' | sort)
python tools/status/render.py --check
# conformance, all four legs and both revisions, plus the era pairs:
make conformance          # or tests/conformance/run.sh <leg> <rev> for each, then era_pairs.py
go test ./internal/proxy/ -run 'TestHTTPPromptAfterFinishedCall|TestOrphan|TestAgentSessionKey|TestHTTPAbandonedCall' -v
```

Conformance was green on all four legs, both revisions, no baseline entry changed, plus `era_pairs` (`agent 2026-07-28 x upstream 2025-11-25: refused per ADR 0014`).

## Decisions made without an ADR

- The **5-minute** orphan TTL is the orchestrator's recommended default, implemented as recommended; the maintainer has not overridden it. It is recorded in ADR 0016's amendment table and in 8.5 as easy to revisit (`defaultOrphanTTL`).
- **One identifier was added to the export surface ADR 0016 pins:** `proxy.ErrMCPGODEBUG` (K4 asked for one refusal text in one place, and two packages cannot share an unexported one). ADR 0016 is amended, not superseded, and 8.5's API paragraph lists it beside `HTTPHandler`, `HTTPOptions` and `HTTPPath`. `HTTPOptions` also gains `OrphanTTL`. Say so if either belongs in its own ADR instead.
- Accepted residual, stated in 8.4, 8.5 and the threat model: with more than one agent session on one upstream, a stateful upstream's prompt is refused for up to `OrphanTTL` after **any** other session's call ends.

## Questions for the receiver

1. Is 5 minutes the right bound, given that J1 makes every ordinary call end block cross-session prompts, or should the TTL for a call the upstream *answered* be shorter than for one that was cancelled?
2. Is the ADR 0014 exception (look-at-this-first #2) acceptable, or should an orphan-refused prompt always carry the unattributed wording?
3. `localAgentKey` assumes one stdio agent session per process (ADR 0012). Is that assumption worth enforcing in code (refuse a second agent session on a stdio proxy) rather than documenting?

## Resolved after this note was written (orchestrator, 2026-09-24)

The export-surface question above is answered: **no new ADR**. The growth stays an in-place amendment of ADR 0016, because that record owns the surface, its decision (one exported entry point; limits as constants, not flags) is unchanged, and its own 2026-09-23 row set the precedent by recording `MaxSessionsPerPrincipal` the same way. The K4 amendment row on `main` now says the "one export" framing reads as one entry point plus its options type, its path constant and one sentinel error, so the earlier row's closed list of three cannot mislead. This differs from the ADR 0012 and 0008 cross-references to ADR 0018 because there a separate record already existed to carry the change; here the growth is internal to the surface ADR 0016 itself owns.

Question 1 above (is 5 minutes right) is still open and is the maintainer's, not the reviewer's, to settle. The reviewer should say whether the bound is *safe*, not whether it is convenient.

PR #75 merged at 2026-09-24 14:37Z as `6a00fc3`, before this security review ran. The review is therefore **post-merge**; a finding becomes a new board task, not a change request on a closed PR.
