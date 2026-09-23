# ADR 0003: YAML policy DSL with obligations

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

Policy must express: allow or deny by device role and command class, hold for approval, force a dry-run and diff before a write, cap fan-out, and give every denial a rule id and a reason. [Research brief 03](../research/03-policy-and-approval-patterns.md) compared OPA/Rego, Cedar, Kyverno-style YAML, Casbin and a custom YAML DSL.

A NetGuard decision is not a boolean. It carries an effect (allow, hold, deny), a rule id, a reason and obligations (`dry_run`, `diff`, `timed_rollback`). OPA and Cedar return authorisation results and do not model obligations natively; Casbin returns a boolean. Network engineers read YAML (Ansible, NetBox exports, containerlab) far more than Rego or Cedar.

The risk of a custom DSL is that it grows into a bad Rego.

## Decision

We will define a small YAML policy DSL evaluated by a pure function `Evaluate(policy, request) -> Decision`, with matchers limited to equality, set membership and numeric ranges, and will add OPA/Rego as an optional backend later that maps its result onto the same `Decision` type.

Rules evaluate in file order; the first match wins and there is no specificity ranking, so rule order is the policy author's precedence. Session caps and the unknown-target default are applied before the rules; an implicit `default:no-match` deny closes the list. Decisions carry `effect`, `rule_id`, `reason`, `obligations[]` and an optional `approval{ttl, approver_must_differ}`. Policies are tested with `netguard policy test` over `*.test.yaml` files so contributors never need a Go toolchain. The normative grammar is [policy-schema.md](../specs/policy-schema.md).

## Consequences

### Positive

- Obligations and reasons are first-class, which is the vocabulary a guardrail needs.
- No sidecar, no Wasm shim, no Rust wheel. Counters and inventory lookups are in-process.
- Table tests over `(request, expected decision)` run in milliseconds.
- A Python `policy-lint` under `tools/` reuses the same schema.

### Negative

- Feature creep. Mitigated by a hard rule: anything beyond equality, set and range goes to the OPA backend, not to the DSL.
- A second engine later means two evaluation paths. Mitigated by the shared `Decision` type and the shared `*.test.yaml` suite, which must pass on both.

### Neutral

- Rego users can keep their policies in Rego once the adapter ships; the audit event records which engine decided.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| OPA/Rego first | Sidecar or Wasm integration from a non-Go host; no native obligations; steep learning curve for network engineers. Kept as an optional backend, embedded in-process since the core is Go ([ADR 0001](0001-go-core-with-python-companion.md)). |
| Cedar | Clean bounded semantics and a live Python binding (`cedarpy`), but low mindshare outside AWS and no obligations. Runner-up. |
| Kyverno-style YAML | No standalone evaluator; would become a custom DSL with Kyverno field names. |
| Casbin | Single matcher expression; returns a boolean; awkward for per-rule reasons and obligations. |

## References

- [Research brief 03, section 1](../research/03-policy-and-approval-patterns.md)
- [OPA integration modes](https://www.openpolicyagent.org/docs/integration)
- [OPA policy testing](https://www.openpolicyagent.org/docs/policy-testing)
- [OPA Go rego package](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego)
- [cedarpy](https://pypi.org/project/cedarpy)
- [Cedar policy validation pipeline sample](https://github.com/aws-samples/cedar-policy-validation-pipeline)
- [pycasbin](https://github.com/apache/casbin-pycasbin)
