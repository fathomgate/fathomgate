# ADR 0025: Split the console: a local console in the core, the team console in the paid edition

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer; decided 2026-09-25); proposed by docs-writer
- Supersedes: the *Approval console* contested row of [ADR 0020](0020-open-core-apache-2.md) and its M5 boundary-table row (R29); settles its M4 "OCSF and CEF exporters (R27)" row as commercial (decision 2). The rest of ADR 0020 is unchanged

## Context

[ADR 0020](0020-open-core-apache-2.md) puts anything that decides what is allowed, or proves what happened, in the Apache-2.0 core, and lets convenience, scale and integrations be commercial. It left the approval console and audit viewer (R29, P0 in M5) contested, recommending it as a commercial candidate on one condition: the core CLI shows the diff, the rule trace and the rule for every pending record, so no one approves blind because the console is absent.

"The console" covers two products with different users:

| | One operator on one machine | A team running many instances |
| --- | --- | --- |
| PRD user | Lab engineer (user 1), a single MSP engineer (user 2) | Platform or security team (user 3), MSPs at scale |
| Needs | Watch the agent, read a held request's diff and rule, approve or deny, check the local audit log | Sign-on, roles, several approvers, one view over many instances, central policy, retention, SIEM |
| ADR 0020 side by its rule | Convenience over data the core already has | Scale and integrations |

Making both commercial leaves the first user with no UI in the open core. Making both open puts scale features in the core that ADR 0020 says may fund the work.

SIEM export raises the same question for the audit log. ADR 0020 lists the OCSF and CEF exporters (R27, P1 in M4) as a commercial candidate, because they read the chain and never write it. The team console's "SIEM export" overlaps with them, so both are settled here.

## Decision

We will ship a local console for one operator on one machine in the core, in M5, and build the team console in the paid edition. We will keep the audit log fully open and put the ready-made OCSF and CEF exporters in the paid edition.

### 1. The console

**Local console (core, Apache-2.0, M5, R29).**

- Served by the `fathomgate` binary itself, loopback only, off by default, no accounts.
- Shows live activity (decision, class, target, rule), each held request with its diff, rule trace and rule, and an audit timeline for the local log with its `fathomgate audit verify` status.
- Approves and denies as the local OS user. That is no stronger than the CLI: an approval from the local console never satisfies `approver_must_differ` on its own, because the agent may run as the same OS user.
- Shows redacted output only and reads the audit chain without writing it (ADR 0020 extension invariants 4 and 5 apply to it as to any extension).
- Its serving, authentication, identity namespace and frontend stack are decided in the local console ADR (ADR 0024, proposed).

**Team console (paid edition, enterprise or team, possibly hosted).** Single sign-on, roles and RBAC, multi-approver and N-of-M approvals, a fleet view across many Fathomgate instances, central policy management, long-term retention and search, and SIEM export through the exporters in decision 2. The rules these feed stay core, as ADR 0020 section 2 requires: the approval state machine, `approver_must_differ`, the policy and the audit chain. No dates or pricing are set here.

**Kept from ADR 0020's condition.** The CLI shows the diff, the rule trace and the rule for every pending record (PRD R35, M3), so the CLI stays complete with neither console present.

### 2. SIEM export

- **Open, unchanged:** the JSONL hash chain, the Ed25519 checkpoints and `fathomgate audit verify` ([ADR 0005](0005-hash-chained-jsonl-audit.md), R26). The log is standard JSON, one record per line, so anyone can forward it to a SIEM with a general log shipper such as Fluent Bit or Vector.
- **Paid edition:** the ready-made OCSF `API Activity` and CEF exporters (R27). They read the JSONL and never write, rewrite or truncate the chain (ADR 0020 extension invariant 5).
- ADR 0020's M4 exporter row, a commercial candidate, is settled as commercial by this decision.

## Consequences

### Positive

- The lab and single-operator user gets a UI in the open core; approving with a diff is a visual task (ADR 0009).
- The line between the editions follows ADR 0020's rule: one machine and one operator is convenience over core data; many users, many instances and integrations are scale.
- The design system in `design/` has an in-repo consumer, so its components are tested where they live.
- Proof stays open: anyone can verify the audit log and forward it to any SIEM without the paid edition.

### Negative

- The core gains a web surface: an HTTP server, a frontend and a browser-facing attack surface on the operator's machine. Mitigation: loopback only and off by default; the local console ADR sets its authentication and threat-model rows before code.
- A local-console approval could be mistaken for a second person's. Mitigation: it never satisfies `approver_must_differ` on its own, and the local console shows why when that rule applies.
- M5 carries more work than a drivers-only milestone. The effort estimate in PLAN.md is revisited when the local console ADR is accepted.
- An open-core operator who needs OCSF or CEF maps the JSONL fields in their own shipper. Mitigation: the log's fields are specified in [audit-event-schema](../specs/audit-event-schema.md), and the JSONL is the stable interface the exporters read too.
- Two consoles on one design system must stay in step. Mitigation: both consume the same `design/tokens.css` and `design/policy.css`; the team console depends on the core, never the reverse.

### Neutral

- R29 changes meaning from "the console" to "the local console". The team console is a new commercial-edition row in PRD.md (R36), and R27 moves from M4 to the paid edition.
- OCSF and CEF stay export formats, never the native format ([ADR 0005](0005-hash-chained-jsonl-audit.md)); only who ships the exporters changes.
- The CLI remains the reference interface: everything either console shows is available from it.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Whole console in the paid edition (the first draft of PR #120) | Leaves the lab and single-operator user with no UI in the open core, although nothing in a one-machine console is scale or integration |
| Whole console in the core | Puts SSO, RBAC, N-of-M approval, fleet view and central policy in the core, the scale features ADR 0020 names as what funds the work |
| No console, CLI only | Rejected in ADR 0009: approving a change with a diff is a visual task |
| OCSF and CEF exporters in the core | Keeping two external schemas in step is ongoing work ([ADR 0005](0005-hash-chained-jsonl-audit.md) *Negative*), and they are integrations under ADR 0020's rule. The open JSONL already reaches any SIEM through a general log shipper |
| Audit log or `audit verify` in the paid edition | Breaks ADR 0020's rule: the chain proves what happened, so it stays open |

## References

- [ADR 0020, open core under Apache-2.0](0020-open-core-apache-2.md): section 2 (boundary rule), the *Approval console* contested row, section 3 (extension invariants)
- [ADR 0009, Fathom design system plus a policy layer](0009-fathom-design-system-policy-layer.md)
- The local console ADR (ADR 0024, proposed)
- [ADR 0004, approval hold state machine](0004-approval-hold-state-machine.md); [approval-protocol](../specs/approval-protocol.md) sections 6.1 and 8
- [ADR 0005, hash-chained JSONL audit](0005-hash-chained-jsonl-audit.md); [audit-event-schema](../specs/audit-event-schema.md) section 8 (exporters)
- [PRD.md requirements](../PRD.md#6-requirements) R27, R29, R35 and R36; [ROADMAP.md](../../ROADMAP.md) stages 5 and 6
