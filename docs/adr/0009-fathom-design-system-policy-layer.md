# ADR 0009: Fathom design system plus a policy layer

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

NetGuard ships one UI in v1, the M5 approval console and audit viewer. The CLI and the audit log are text, but they name the same states. A guardrail has states that a topology tool does not: a call is allowed, holding, denied or expired; a secret is redacted; a blast radius is within or over a cap. Those states need names, colours and components that are identical everywhere, because a screenshot and a log line must describe one event in one vocabulary.

Fathom is the author's existing two-theme design system (Midnight Zone dark, Chart Room light) with semantic tokens and a contrast table.

## Decision

We will use Fathom unchanged and add one policy layer in `design/` that names the guardrail states, with every policy token aliasing a Fathom semantic token and no new hue, font or spacing step.

| State | Word shown | Token | Fathom source |
| --- | --- | --- | --- |
| allow | Allowed | `--decision-allow` | `success` |
| hold | Holding | `--decision-hold` | `warning` |
| deny | Denied, always with the rule id | `--decision-deny` | `danger` |
| expired | Expired | `--decision-expired` | `text-disabled` |
| redacted (not a decision) | `hmac:3f9a…` dashed token | `--redacted` | `accent` |

Components are prefixed `ng-`: decision badge, command-class chip (outline only), redacted token, diff view, approval card, TTL bar, blast-radius meter (four discrete bands), audit timeline, rule trace. Voice rules: every denial names its rule; verbs match the state machine with no synonyms; a rule id is a technical value set in mono. The CLI prints decision, class, target, rule and reason in the console's order; audit JSONL field names are the console's meta labels lowercased.

## Consequences

### Positive

- One vocabulary across UI, CLI, audit log and docs, enforced by design rather than by review.
- Both themes work with no per-component overrides.
- Contributors get `design/DESIGN.md` and `design/preview.html` as the reference.

### Negative

- The console depends on a design system not published as a package. Mitigated by vendoring `tokens.css` and `policy.css` in the repo.
- A fifth decision state cannot be added without an ADR. That is intended.

### Neutral

- The design layer lands before the console (M5) because the words are used from M1 in the CLI.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A new design system | Cost with no benefit; the states are the only new thing. |
| Off-the-shelf component library | Would not carry the decision vocabulary or the two-theme contrast guarantees. |
| No console, CLI only | Approval with a diff is a visual task; M5 adds the console while keeping the CLI complete. |

## References

- [design/DESIGN.md](../../design/DESIGN.md)
- [Fathom design system](https://claude.ai/artifact/EAmcPjFiSHKMwpBX9oj8Gf)
- [NetGuard Console preview](https://claude.ai/artifact/VpFRDQdCrxp1Bu4LWmMeFM)
- [PLAN.md, design system](../PLAN.md)
