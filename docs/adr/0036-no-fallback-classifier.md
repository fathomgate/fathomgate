# ADR 0036: No fallback classifier; a tool with no profile entry is `EXEC_ARBITRARY`

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), decided 2026-09-25; drafted by docs-writer in PR #194 (board task M1-24) from the security review of that PR
- Supersedes in part: [ADR 0010](0010-classify-by-payload-not-annotations.md), the fallback classifier for unmapped tools only. Payload classification, the downgrade rule and annotations that only raise are unchanged.
- Related: [ADR 0027](0027-serve-policy-inventory-profiles-flags.md) (the empty profile under `--policy`), [ADR 0033](0033-closed-argument-list-per-tool.md) (the closed argument list), board task M1-15

## Context

[ADR 0010](0010-classify-by-payload-not-annotations.md) decided to classify with "a per-server profile as the primary mapping and a fallback classifier for unmapped tools". [classification.md](../specs/classification.md) section 3 then specified that fallback: ordered rules on the tool's name and argument names (`^(show|get|...)` gives `READ_OPERATIONAL`, `(config|running|...)` gives `READ_CONFIG`, and so on), and the PLAN M1 row lists it as a deliverable.

It was never built. The code on `main` gives a tool with no profile entry `EXEC_ARBITRARY` with `class_source: fallback` and never downgrades it. Under `fathomgate serve --policy` it goes further: a server with no profile gets an empty one (ADR 0027, note of 2026-09-25), and the gate denies any call that carries an argument to a tool the profile does not list, by rule `default:bad_arguments` (ADR 0033 section 2). The M1-24 reconciliation found the spec, PLAN, ADR 0020, ADR 0026, ADR 0027, ADR 0033 and ARCHITECTURE still describing the fallback, and board task M1-15 asking for tests of it.

## Decision

We will not build the section 3 fallback classifier. A tool with no profile entry is classified by what it is not: unknown.

1. A tool with no profile entry is `EXEC_ARBITRARY`, `class_source: fallback`, and is never downgraded. The audit event (M4) carries `profile_gap: true`; in M1 the decision log line shows `class_source=fallback`.
2. Under `--policy`, any call to such a tool that carries an argument is denied by rule `default:bad_arguments`, before `Evaluate` (ADR 0033). This includes every tool of a server with no profile, which gets an empty one (ADR 0027).
3. A call with no arguments reaches the rules as `EXEC_ARBITRARY` with zero targets, so the unknown-target default and `max_devices` do not apply and no `device_roles` or `device_tags` rule matches it. A policy that denies `EXEC_ARBITRARY` denies it.

The fix for a tool with no profile entry is a profile entry. If rules on tool names are ever wanted, they belong in an offline authoring aid that proposes a profile entry for a person to review, never in the proxy at run time.

## Consequences

### Positive

- An upstream cannot choose its own class. Tool names are untrusted upstream data (invariant 7); with name rules, a rug-pulled upstream could rename `run_command` to `show_command` and be classified `READ_OPERATIONAL` (MCP03).
- Nothing can be loosened by a missing profile. Under the empty profile the fallback could only ever have made an unlisted tool less strict than `EXEC_ARBITRARY`.
- The spec matches the code: the gate never calls a fallback, and there is no second classification path to test and keep in step.

### Negative

- A call with no arguments to a tool with no profile entry reaches the rules with zero targets. If a policy allows `EXEC_ARBITRARY` in a rule without `device_roles` or `device_tags`, such a call is forwarded, with unknown and possibly fleet-wide effect, and no device count or unknown-target check applies. Accepted residual (security review of PR #194, L2); the example policies deny `EXEC_ARBITRARY`.
- A new upstream does not work on day one beyond calls with no arguments: every useful call is denied until a profile maps its tools. Mitigated by the profile library, the `serve` start-up warning that names the servers with a profile, and `--profiles` for an operator's own profile.
- Board task M1-15 (fallback tests for every other surveyed tool in brief 02) changes meaning: it can pin that each such tool is `EXEC_ARBITRARY`, or its calls with arguments `default:bad_arguments`, not a class from its name. The PRD metric stays as written ("every remaining surveyed tool at least fallback-classified with a test", PRD section 5); a test that such a tool is `EXEC_ARBITRARY` with `class_source: fallback` meets it.

### Neutral

- `class_source: fallback` keeps its name and meaning: the tool had no profile entry.
- ADR 0010's annotation rule, payload inspection and downgrade are unchanged.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Build section 3 as specified | Tool names and argument names come from the upstream, so an upstream picks its class by naming a tool; the empty profile means it could only loosen; the gate never calls it; section 3 itself says the fix is a profile entry. |
| Build section 3 but only allow it to raise | Nothing is stricter than `EXEC_ARBITRARY`, so it would never change a result. |
| Name rules in an offline authoring aid | Not rejected: allowed as a tool that proposes profile entries for review. Never at run time. |

## References

- [classification.md](../specs/classification.md) sections 2, 3 and 9
- [profile-schema.md](../specs/profile-schema.md) section 2.2 (targets at the gate, a server with no profile)
- `internal/gate/gate.go` (`classify`: a tool not in the profile is `EXEC_ARBITRARY`, `class_source: fallback`), `cmd/fathomgate/serve_policy.go` (the empty profile and its warning)
- [Threat model](../security/threat-model.md), row "Upstream-controlled tool names choose the class"
- Security review of PR #194 (M1-24)
