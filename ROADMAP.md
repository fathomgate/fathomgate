# Roadmap

Milestones from `docs/PLAN.md`, with the state of this tree. Each milestone
is shippable and validated against at least one real upstream server before
the next starts.

| Milestone | Scope | Status |
| --- | --- | --- |
| **M1 building blocks** (this tree) | `internal/policy` DSL + `Evaluate` + `netguard policy test`; `internal/classify` profiles, normaliser and fallback command classifier; `internal/redact` vendor patterns with keyed HMAC and the fixture corpus; `internal/audit` hash chain, Ed25519 checkpoints and `audit verify`; `internal/inventory` static file, hostname patterns and CSV import; CLI, GoReleaser, Dockerfile, CI | done, no proxy yet |
| **M0 pass-through** | Go proxy that spawns one stdio upstream, forwards `tools/list` and `tools/call` with the server prefix, speaks both the 2025 (stateful) and 2026 (stateless, MRTR) protocol eras | **in progress**: toolchain unblocked. `go.mod` is on Go 1.25 with `github.com/modelcontextprotocol/go-sdk` v1.7.0 pinned (T0.1). `internal/proxy` is next (T0.2); until it lands, `netguard serve` exits 2. |
| M1 classify + allow/deny (wire-up) | Run the pipeline inside the proxy: normalise, classify, resolve, evaluate, structured deny errors that name the rule; upstream `INVENTORY_READ` as a resolver | after M0 |
| M2 role-aware policy + redaction | NetBox and Nautobot resolver with TTL cache, `inventory sync` snapshot and `sot: stale` marking; redactor at the response serialiser; TOFU description pinning | `internal/inventory/netbox.go` is the stub |
| M3 dry-run, diff, approval hold | `ChangeSafety` drivers for Junos and EOS; SQLite pending queue with TTL; `netguard approve`/`deny`; HMAC webhook; MRTR elicitation; drift guard | not started |
| M4 audit chain + blast radius | Wire `internal/audit` into the proxy; OCSF and CEF exporters; session counters, fan-out caps, canary-first rule, maintenance windows | chain and verify done; exporters and wiring pending |
| M5 console + watchdog drivers | Approval console (Fathom policy layer in `design/`); IOS-XE, NX-OS, PAN-OS, FortiOS drivers with proxy-owned rollback watchdog; optional OPA backend | not started |

## Unblocking M0

1. Done (T0.1): `go.mod` is on `go 1.25.0`.
2. Done (T0.1): `github.com/modelcontextprotocol/go-sdk v1.7.0` is pinned via
   `internal/tools/tools.go` (`//go:build tools`). Step 3 replaces that import.
3. Implement `internal/proxy`: `mcp.Server` toward the client, one
   `mcp.Client` per upstream using `CommandTransport`, tool-name prefixing,
   and the pipeline call in the `tools/call` handler.
4. Run the official conformance suite against the client-facing side and
   wire it into `.github/workflows/ci.yaml` as tier 2.
5. Un-skip `tests/integration/test_passthrough.py`.

## Open questions

Tracked in `docs/PLAN.md` "Open questions and risks": project name, MRTR
timing, stale-snapshot cap, key custody for the audit and redaction keys,
IOS-XR and SR Linux in the first driver set, agentgateway ext-proc plugin.
