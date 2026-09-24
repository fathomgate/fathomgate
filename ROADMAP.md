# Roadmap

Milestones from `docs/PLAN.md`, with the state of this tree. Each milestone
is shippable and validated against at least one real upstream server before
the next starts.

| Milestone | Scope | Status |
| --- | --- | --- |
| **M1 building blocks** (this tree) | `internal/policy` DSL + `Evaluate` + `fathomgate policy test`; `internal/classify` profiles, normaliser and fallback command classifier; `internal/redact` vendor patterns with keyed HMAC and the fixture corpus; `internal/audit` hash chain, Ed25519 checkpoints and `audit verify`; `internal/inventory` static file, hostname patterns and CSV import; CLI, GoReleaser, Dockerfile, CI | done, no proxy yet |
| **M0 pass-through** | Go proxy that spawns one stdio upstream, forwards `tools/list` and `tools/call` with the server prefix, speaks both the 2025 (stateful) and 2026 (stateless, MRTR) protocol eras | **in progress**: `go.mod` is on Go 1.26 (toolchain go1.26.8; ADR 0015) with `github.com/modelcontextprotocol/go-sdk` v1.8.0. `fathomgate serve` spawns one stdio upstream and forwards `tools/list` and `tools/call` with the `<server>.` prefix, pass-through only (T0.2). Dual-era negotiation, `_meta` isolation and origin-labelled MRTR and elicitation passthrough are merged (T0.3; [ADR 0014](docs/adr/0014-stateful-upstream-prompts-to-stateless-agents.md)). `make conformance` and the `mcp-conformance` CI job run the official suite for both eras with a per-check baseline (T0.4); open gaps are T0.17 to T0.19. Client smoke (T0.5) is next. |
| M1 classify + allow/deny (wire-up) | Run the pipeline inside the proxy: normalise, classify, resolve, evaluate, structured deny errors that name the rule; upstream `INVENTORY_READ` as a resolver | after M0 |
| M2 role-aware policy + redaction | NetBox and Nautobot resolver with TTL cache, `inventory sync` snapshot and `sot: stale` marking; redactor at the response serialiser; TOFU description pinning | `internal/inventory/netbox.go` is the stub |
| M3 dry-run, diff, approval hold | `ChangeSafety` drivers for Junos and EOS; SQLite pending queue with TTL; `fathomgate approve`/`deny`; HMAC webhook; MRTR elicitation; drift guard | not started |
| M4 audit chain + blast radius | Wire `internal/audit` into the proxy; OCSF and CEF exporters; session counters, fan-out caps, canary-first rule, maintenance windows | chain and verify done; exporters and wiring pending |
| M5 console + watchdog drivers | Approval console (Fathom policy layer in `design/`); IOS-XE, NX-OS, PAN-OS, FortiOS drivers with proxy-owned rollback watchdog; optional OPA backend | not started |

## Unblocking M0

1. Done (T0.1, T0.14, ADR 0015): `go.mod` is on `go 1.26.0` with toolchain `go1.26.8`.
2. Done (T0.1, ADR 0011): `github.com/modelcontextprotocol/go-sdk` is pinned to one minor, currently v1.8.
3. Done (T0.2, T0.3): `internal/proxy` with `mcp.Server` toward the client,
   one `mcp.Client` per upstream using `CommandTransport`, tool-name
   prefixing and both protocol eras. The pipeline call goes in
   `Proxy.dispatch` in M1.
4. Done (T0.4): the official conformance suite runs against the
   client-facing side for both eras (`make conformance`, CI job
   `mcp-conformance`), with expected failures listed per check in
   `tests/conformance/baseline/`. Progress relay (T0.17) and retry
   handling (T0.18) close the remaining gaps for exit criterion 1.
5. Client smoke (T0.5): un-skip `tests/integration/test_passthrough.py`.

## Open questions

Tracked in `docs/PLAN.md` "Open questions and risks": project name, MRTR
timing, stale-snapshot cap, key custody for the audit and redaction keys,
IOS-XR and SR Linux in the first driver set, agentgateway ext-proc plugin.
