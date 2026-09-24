# Architecture decision records

One record per decision that would be expensive to reverse. Records follow [MADR](https://adr.github.io/madr/) with the sections in [0000-template.md](0000-template.md). A record is never edited after acceptance except to change its status, or to correct a fact without changing the decision (dated in its `Amendments` section, per [GOVERNANCE.md](../../GOVERNANCE.md#architecture-decisions)); any change to the decision needs a new record that supersedes it.

To propose one, copy the template to the next number, open a pull request, and link the record from the code or spec it governs. See [GOVERNANCE.md](../../GOVERNANCE.md) for how records are accepted.

Records before [ADR 0019](0019-rename-to-fathomgate.md) use the placeholder name NetGuard and the identifiers in that record's scope table (`netguard`, `NETGUARD_*`, `ng3.`, `netguard-orchestrator`), and are left as written; the scope table maps each one to its Fathomgate name.

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
| [0011](0011-accept-go-sdk-transitive-modules.md) | Accept go-sdk and its transitive modules | accepted | 2026-09-23 |
| [0012](0012-serve-cli-and-proxy-api-for-m0.md) | `netguard serve` flags and the `internal/proxy` API for M0 | accepted | 2026-09-23 |
| [0013](0013-pin-go-toolchain-in-go-mod.md) | Pin the Go build toolchain in go.mod | accepted | 2026-09-23 |
| [0014](0014-stateful-upstream-prompts-to-stateless-agents.md) | Refuse a stateful upstream's prompt to a stateless agent in M0; defer parking to row 17 | accepted | 2026-09-23 |
| [0015](0015-raise-go-floor-to-1-26.md) | Raise the go floor to 1.26.0 and let it follow the oldest supported Go release | accepted | 2026-09-23 |
| [0016](0016-streamable-http-listener.md) | A Streamable HTTP listener for `netguard serve`, loopback-only and token-authenticated | accepted | 2026-09-23 |
| [0017](0017-keep-upstream-secrets-off-the-command-line.md) | Keep upstream secrets off the command line with `--upstream-env-pass` | accepted | 2026-09-23 |
| [0018](0018-bound-server-discover-then-initialize-only.md) | Bound go-sdk's `server/discover` probe, then restart the upstream and connect with `initialize` only | accepted | 2026-09-24 |
| [0019](0019-rename-to-fathomgate.md) | Rename the product from NetGuard to Fathomgate | accepted | 2026-09-24 |
| [0020](0020-open-core-apache-2.md) | Open core under Apache-2.0, with outside contributions by DCO sign-off | proposed | 2026-09-24 |

Decisions still open are listed in [PLAN.md](../PLAN.md#open-questions-and-risks) and [PRD.md](../PRD.md#7-open-questions). Each will become a record when resolved.
