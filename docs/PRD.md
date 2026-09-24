# Product requirements

NetGuard is a policy-enforcing MCP proxy that sits between any AI agent and any network-device MCP server. It classifies every tool call by what it does to the network, resolves the target device's role, evaluates a YAML policy, and allows, holds or denies the call. Every result is redacted and audited. This document says who it is for, what it must do, and how success is measured.

Plan: [PLAN.md](PLAN.md). Architecture: [ARCHITECTURE.md](../ARCHITECTURE.md). Milestones: [ROADMAP.md](../ROADMAP.md).

## 1. Problem

Network MCP servers give agents SSH, eAPI, NETCONF and REST access to routers, switches and firewalls. Of 25 surveyed servers, most expose a free-form "run a command" tool; only three enforce a positive allow-list; only one redacts secrets; several auto-commit configuration with no dry run ([research brief 02](research/02-network-mcp-servers.md)). Safety is being added one server at a time (Junos `block.cmd`, OPNsense read-only mode, UniFi read-only mode).

Generic MCP gateways do authentication and tool-name allow-lists but do not know what a device, a config or a commit is, do not inspect arguments, and do not hold calls for a human ([research brief 01](research/01-mcp-proxy-prior-art.md)). A poisoned tool description or an injected `show` output can steer an agent into `write erase`, and nothing in the path today would stop it.

## 2. Users

| User | Situation | What they need |
| --- | --- | --- |
| Network engineer running agents in a lab | Runs Claude Code or Cursor against a containerlab or home lab through eos-mcp, netdev-ssh-mcp or a netmiko server. Wants to let the agent do real work without a `reload` surprise. | One binary, one `mcp.json` entry, a read-only policy on day one, lab writes with dry-run and diff on day two. |
| MSP engineer fronting client devices | Runs one proxy per client. Has a spreadsheet, not NetBox. Must show the client what the agent did. | Static inventory from CSV, per-client policy, an audit log a client can verify, approval by a second engineer for production writes. |
| Platform or security team governing agent access | Owns NetBox or Nautobot. Runs agentgateway or ContextForge for auth. Needs evidence for audit and a hard stop on unknown devices. | Role resolution from the source of truth with stale marking, OCSF or CEF export, HMAC webhook approval from the ticketing system, an optional OPA backend. |

## 3. Jobs to be done

1. When an agent calls a tool on a device, decide in milliseconds whether it is a read, a config read, a write or arbitrary execution, without trusting the tool's name or annotations.
2. When the call is a write to a production device, show a human the diff and let them approve or deny it within a TTL, from the CLI, a Slack button or in-band.
3. When a change is applied, make it roll back automatically unless confirmed.
4. When device output returns, remove every secret before the agent sees it, in a way that still lets an operator compare values.
5. When anyone asks what an agent did, produce a tamper-evident record tying principal, device, command, decision, rule, approver and diff.
6. When a target is not in inventory, refuse to change it.
7. When an upstream server changes its tool descriptions, stop trusting it until reviewed.

## 4. Non-goals

- Authentication federation, OAuth, token exchange. A generic gateway or the MCP host does this.
- OpenTelemetry pipelines. NetGuard emits audit JSONL and exports OCSF and CEF.
- Being an MCP server for devices. NetGuard never opens SSH; the upstream does.
- Catalogues, virtual servers, REST-to-MCP conversion.
- Intent verification or reachability analysis. Batfish is a possible later obligation, not a requirement.
- Replacing upstream safety features. NetGuard is defence in depth in front of them.

## 5. Success metrics

### M1 (classify plus allow and deny)

| Metric | Target |
| --- | --- |
| Surveyed tools mapped in profiles | 100 percent of the tools in research brief 02 for the first three upstreams; every remaining surveyed tool at least fallback-classified with a test |
| `reload` through a free-form tool on any first upstream | Denied by rule id, in tier 1 and tier 2 |
| `show ip bgp summary` through an unfiltered tool | Downgraded to `READ_OPERATIONAL` and allowed |
| Policy tests | `netguard policy test policies/` green with at least three cases per example policy |
| Proxy overhead per call | Under 5 ms at p99 for classify plus evaluate, measured in tier 1 |
| Install | `mcp.json` with the binary path works in Claude Code and one other client with no ENOENT |

### M5 (console and watchdog drivers)

| Metric | Target |
| --- | --- |
| Held write on a `core` device | Diff shown, executes once on approval, expires on TTL, refuses on drift, in tier 2 |
| Unconfirmed NX-OS change | Rolled back by the watchdog at the deadline on a containerlab device, tier 3 |
| Redaction | Every annotated line in the fixture corpus caught; zero gitleaks findings on sampled tier 2 output |
| Audit | Any single edited line fails `netguard audit verify` |
| Console | Shows pending, approved and denied calls live in both themes |
| Time from `hold` to approver notification | Under 5 seconds via webhook |

## 6. Requirements

Priority: P0 ships in the named milestone or the milestone does not ship; P1 ships in the milestone if time allows, otherwise the next; P2 is planned.

| Id | Requirement | Priority | Milestone | Spec |
| --- | --- | --- | --- | --- |
| R1 | Proxy one stdio upstream; forward `tools/list` and `tools/call`; prefix tool names with the profile id | P0 | M0 | [ARCHITECTURE](../ARCHITECTURE.md) |
| R2 | Speak 2025-11-25 stateful and 2026-07-28 stateless eras on both sides | P0 | M0 | [ADR 0008](adr/0008-dual-era-mcp-support.md) |
| R3 | Pass the official conformance suite on the client-facing side in CI | P0 | M0 | [test-strategy](testing/test-strategy.md) |
| R4 | Single static binary for linux, darwin, windows via GoReleaser; distroless image | P0 | M0 | [ADR 0001](adr/0001-go-core-with-python-companion.md) |
| R5 | Normalise `target`, `targets[]`, `commands[]`, `config_payload` from per-server profiles | P0 | M1 | [profile-schema](specs/profile-schema.md) |
| R6 | Classify every call into one of seven classes by payload; annotations only raise | P0 | M1 | [classification](specs/classification.md) |
| R7 | Downgrade `EXEC_ARBITRARY` to `READ_OPERATIONAL` only when every command passes allow-list, blocklist and pipe rules | P0 | M1 | [classification](specs/classification.md) |
| R8 | Reclassify config reads through free-form tools as `READ_CONFIG` | P0 | M1 | [classification](specs/classification.md) |
| R9 | YAML policy with `Evaluate`; strict first match in file order; implicit deny when no rule matches; obligations | P0 | M1 | [policy-schema](specs/policy-schema.md) |
| R10 | `netguard policy test` over `*.test.yaml` | P0 | M1 | [policy-schema](specs/policy-schema.md) |
| R11 | Denied calls return a tool error naming rule id and reason | P0 | M1 | [ADR 0009](adr/0009-fathom-design-system-policy-layer.md) |
| R12 | Static inventory file and CSV import; hostname patterns; unknown targets denied for writes and exec | P0 | M1 | [inventory-schema](specs/inventory-schema.md) |
| R13 | Meta-tool classification through capability tables | P1 | M1 | [profile-schema](specs/profile-schema.md) |
| R14 | Upstream inventory provider via `INVENTORY_READ` tools | P1 | M2 | [inventory-schema](specs/inventory-schema.md) |
| R15 | NetBox and Nautobot resolver with cache, snapshot sync and `sot: stale` marking | P0 | M2 | [inventory-schema](specs/inventory-schema.md) |
| R16 | Redaction with vendor grammar and keyed truncated HMAC at the serialiser | P0 | M2 | [redaction-patterns](specs/redaction-patterns.md) |
| R17 | TOFU pinning of upstream tool descriptions; quarantine on change | P0 | M2 | [ADR 0008](adr/0008-dual-era-mcp-support.md) |
| R18 | `ChangeSafety` drivers for Junos and EOS | P0 | M3 | [change-safety-drivers](specs/change-safety-drivers.md) |
| R19 | Pending store in SQLite with TTL; expiry terminal | P0 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R20 | Approve and deny via CLI and HMAC webhook | P0 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R21 | Approve via MRTR elicitation for 2026-era clients | P1 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R22 | Drift guard: re-run dry-run at approval, cancel on diff hash change | P0 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R23 | Idempotent execution keyed by pending id | P0 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R24 | `approver_must_differ` enforced on server-side identities | P0 | M3 | [approval-protocol](specs/approval-protocol.md) |
| R25 | Re-label upstream elicitation prompts with origin | P1 | M3 | [ADR 0008](adr/0008-dual-era-mcp-support.md) |
| R26 | Hash-chained JSONL with Ed25519 checkpoints and `audit verify` | P0 | M4 | [audit-event-schema](specs/audit-event-schema.md) |
| R27 | OCSF `API Activity` and CEF exporters | P1 | M4 | [audit-event-schema](specs/audit-event-schema.md) |
| R28 | Session counters, fan-out caps, canary-first rule, maintenance windows | P0 | M4 | [policy-schema](specs/policy-schema.md) |
| R29 | Approval console and audit viewer using the Fathom policy layer | P0 | M5 | [ADR 0009](adr/0009-fathom-design-system-policy-layer.md) |
| R30 | IOS-XE, NX-OS, PAN-OS, FortiOS drivers with proxy watchdog | P0 | M5 | [change-safety-drivers](specs/change-safety-drivers.md) |
| R31 | Optional OPA backend mapping onto `Decision` | P2 | M5 | [ADR 0003](adr/0003-yaml-policy-dsl-with-obligations.md) |
| R32 | Block and audit upstream `sampling/createMessage` | P1 | M2 | [ADR 0008](adr/0008-dual-era-mcp-support.md) |
| R33 | Policy reload on SIGHUP without dropping connections; failed reload keeps the old policy | P1 | M1 | [policy-schema](specs/policy-schema.md) |
| R34 | Python `tools/policy-lint` sharing the YAML schema and classifier tables | P1 | M1 | [CONTRIBUTING](../CONTRIBUTING.md) |

## 7. Open questions

Carried from [PLAN.md](PLAN.md). Each becomes an ADR when resolved.

| Question | Decides | Needed by |
| --- | --- | --- |
| Final name; NetGuard collides with existing products. Decided: Fathomgate, [ADR 0019](adr/0019-rename-to-fathomgate.md) (accepted 2026-09-24; rename is T0.49) | Repository name, binary name, prefix conventions | First public commit |
| Which MCP clients the first users run | Whether R21 (MRTR approval) ships in M3 or later | M3 planning |
| Whether the stale-snapshot window is capped | `sot.stale_max_age` default | M2 |
| Key custody for audit checkpoints and the redaction HMAC: file, OS keyring, KMS | Startup requirements, docs, threat model | M2 for redaction, M4 for checkpoints |
| Whether IOS-XR and Nokia SR Linux join the first driver set | M3 or M5 scope; both have native commit-confirmed | M3 planning |
| Whether to offer the policy layer as an ext-proc plugin for agentgateway | Post-M5 roadmap | After M5 |

## 8. Risks

See the risk table in [PLAN.md](PLAN.md#open-questions-and-risks). The two that shape requirements most: upstream servers change tool schemas without notice (R17 and weekly tier 2 CI answer it), and regex redaction fails open on unseen formats (the fixture corpus, gitleaks canary and allow-list mode answer it).
