<!-- Title: conventional commit form, e.g. "feat(classify): add FortiOS allow-list" -->

## What

One or two sentences. What changes for an agent, operator or approver.

## Why

Link the issue, ADR or spec section. If this changes behaviour, say which decision, class or state it affects, using the words in docs/glossary.md.

## Validation

- Tier 1: `make test` result.
- Tier 2, if `internal/proxy`, `profiles/` or `tests/images/` changed: `make test-integration` result and the real upstream it ran against.
- Tier 3, if a driver changed and an image was available: result.

## Checklist

- [ ] ADR: this change does not alter a spec, the class list, a decision word, a trust boundary or a format; or an ADR is included or linked.
- [ ] Policy tests: any change to `internal/policy` or `policies/` comes with `*.test.yaml` cases, and `netguard policy test policies/` passes.
- [ ] Classification tests: any change to allow-lists, blocklists or profiles has a positive and a negative case, and the worked examples in `docs/specs/classification.md` are updated if a row changed.
- [ ] Redaction fixtures: any new or changed pattern has an annotated line in `tests/fixtures/configs/`, and no real secret appears anywhere in this pull request.
- [ ] Profile parity: a profile change was checked against the upstream's `tools/list` (tier 2) or the source line is cited in `notes`.
- [ ] Docs updated: the spec, ARCHITECTURE.md, ROADMAP.md, CHANGELOG.md (Unreleased) or glossary, whichever this touches.
- [ ] Vocabulary: decisions are allow, hold, deny, expired; states are Holding, Approved, Denied, Expired, Cancelled, Executed, Failed; every denial names its rule.
- [ ] Python parity: if the YAML schema or classifier tables changed, `tools/policy-lint` was updated too.
- [ ] Commits are signed off (DCO) and follow Conventional Commits.
- [ ] No new dependency, or the reason is stated above. `gopkg.in/yaml.v3` is not used.
