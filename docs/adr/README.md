# Architecture decision records

One record per decision that would be expensive to reverse. Records follow [MADR](https://adr.github.io/madr/) with the sections in [0000-template.md](0000-template.md). A record is never edited after acceptance except to change its status; a new record supersedes it.

To propose one, copy the template to the next number, open a pull request, and link the record from the code or spec it governs. See [GOVERNANCE.md](../../GOVERNANCE.md) for how records are accepted.

| Number | Title | Status | Date |
| --- | --- | --- | --- |
| [0001](0001-go-core-with-python-companion.md) | Go core with a Python companion | accepted | 2026-09-23 |
| [0002](0002-standalone-proxy-not-gateway-plugin.md) | Standalone proxy, not a gateway plugin | accepted | 2026-09-23 |
| [0003](0003-yaml-policy-dsl-with-obligations.md) | YAML policy DSL with obligations | accepted | 2026-09-23 |
| [0004](0004-approval-hold-state-machine.md) | Approval hold state machine | accepted | 2026-09-23 |
| [0005](0005-hash-chained-jsonl-audit.md) | Hash-chained JSONL audit log | accepted | 2026-09-23 |
| [0006](0006-keyed-hmac-redaction.md) | Keyed HMAC redaction | accepted | 2026-09-23 |
| [0007](0007-role-resolver-chain-sot-optional.md) | Role resolver chain with the source of truth optional | accepted | 2026-09-23 |
| [0008](0008-dual-era-mcp-support.md) | Dual-era MCP support | accepted | 2026-09-23 |
| [0009](0009-fathom-design-system-policy-layer.md) | Fathom design system plus a policy layer | accepted | 2026-09-23 |
| [0010](0010-classify-by-payload-not-annotations.md) | Classify by payload, not by annotations | accepted | 2026-09-23 |
| [0011](0011-accept-go-sdk-transitive-modules.md) | Accept go-sdk v1.7.0 and its transitive modules | accepted | 2026-09-23 |
| [0012](0012-serve-cli-and-proxy-api-for-m0.md) | `netguard serve` flags and the `internal/proxy` API for M0 | accepted | 2026-09-23 |
| [0013](0013-pin-go-toolchain-in-go-mod.md) | Pin the Go build toolchain in go.mod | accepted | 2026-09-23 |
| [0014](0014-stateful-upstream-prompts-to-stateless-agents.md) | Refuse a stateful upstream's prompt to a stateless agent until parking is decided | proposed | 2026-09-23 |

Decisions still open are listed in [PLAN.md](../PLAN.md#open-questions-and-risks) and [PRD.md](../PRD.md#open-questions). Each will become a record when resolved.
