# T0.39's decision record is proposed in PR #74; the code waits on its acceptance

- **Task:** T0.39 — Stop netguard hanging at startup on upstreams that never answer server/discover (probe timeout, restart, straight to initialize)
- **From → To:** docs-writer → mcp-protocol-engineer
- **State now:** in progress (ADR `proposed`; code not opened)
- **Branch / PR:** `docs/adr-0018-discover-probe-timeout` · https://github.com/joshscott13/netguard/pull/74
- **Date:** 2026-09-24

## Done

- `docs/adr/0018-bound-server-discover-then-initialize-only.md`, status `proposed`: bound go-sdk's `server/discover` probe at 5 seconds; on a deadline, restart the upstream and connect again with `&mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"}` so go-sdk skips the probe; one `warn` line; the second attempt is the last; no CLI flag and no profile field in M0.
- Index row in `docs/adr/README.md`.
- The record amends [ADR 0008](../adr/0008-dual-era-mcp-support.md) and the profile-schema 8.4 bullet "Upstream, once at connect", and names the `proxy.Upstream` change that [ADR 0012](../adr/0012-serve-cli-and-proxy-api-for-m0.md)'s API list will need.
- Four alternatives closed, two recorded as open: a flag or per-upstream field to force the era, and the upstream fix in go-sdk and the Python SDK (the T0.36 path).

## Look at this first

- The **Decision** section of ADR 0018. Two clauses cost implementation work beyond the timeout: the restart is mandatory (the probe can leave the upstream answering nothing, observed in `test_locked_upstream_stops_answering_after_server_discover`), and `proxy.Upstream` has to carry something that builds a transport twice, because `mcp.CommandTransport` holds one `exec.Cmd` while `proxy.Command.Transport()` already returns a fresh one per call. The exact exported shape is yours to choose; record it in ADR 0012's API list and profile-schema 8.3 in the code PR.

## Deliberately unfinished

- No Go. The ADR is `proposed`; per `GOVERNANCE.md` the maintainer merges it as `accepted`, and code cannot open before that.
- `docs/milestones/M0.yaml` is untouched: PR #73 is mid-sync and the orchestrator records the ADR reference against T0.39 afterwards. Only `STATUS.md`'s handoff table is re-rendered here.
- The spec deltas (profile-schema 8.3 and 8.4) and the ADR 0012 API row belong in your code PR, not this one, so they land with the behaviour they describe.
- `tests/integration/test_upa_netmiko.py`: the strict xfail `test_locked_upstream_initialises_behind_netguard` passes once this lands, so its marker must be removed in the same PR, and matrix row 2's T0.39 caveat with it.

## Reproduce green

```sh
python tools/status/render.py --check          # STATUS.md is current
# docs only; no Go changed, so the build and test gates are unaffected by this branch.
```

## Decisions made without an ADR

- None. Every claim in the record is cited to go-sdk v1.8.0 source, `internal/proxy`, or a named test in `tests/integration/test_upa_netmiko.py`; upstream behaviour is written as observed, not as guaranteed.

## Questions for the receiver

- Do you want T0.25 (the upstream's exit status at startup) in the same code PR? The board says "do with T0.39", and both touch the same startup path.
- 5 seconds is the maintainer's number. If the restart plus the second handshake turns out to be slow against a real upstream, say so before the code PR rather than changing the constant in it.
