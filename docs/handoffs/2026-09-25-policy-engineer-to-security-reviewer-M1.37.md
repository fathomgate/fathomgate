# M1.37: an unset unknown_target now denies every class (ADR 0032); security review

- **Task:** M1.37, Make an unset unknown_target deny every class (ADR)
- **From → To:** policy-engineer → security-reviewer (go-reviewer is the second reviewer)
- **State now:** in review. M1-37 is on the board only on PR #159's branch; this PR does not edit `docs/milestones/`.
- **Branch / PR:** `feat/unknown-target-default-deny` · [PR #160](https://github.com/fathomgate/fathomgate/pull/160)
- **Date:** 2026-09-25

## Done

- `docs/adr/0032-unset-unknown-target-denies-every-class.md`, accepted (maintainer decision 2026-09-25). ADR 0007 gets an `Amended by:` line and a dated *Amendments* row. ADR 0026 does not state the default and is unchanged.
- `internal/policy/load.go`: `Parse` fills an unset `defaults.unknown_target` in as `deny`.
- `internal/policy/evaluate.go` step 1: any value other than `allow` denies with `default:unknown_target`. The step still comes first and uses the same id and text.
- `TestUnknownTargetDefaults` is rewritten: unset, `deny` and `allow` across all seven classes, one unknown target alone and among known ones, a `Policy` built without `Parse`, targetless requests, and known targets.
- Docs: policy-schema 2.1, 4 and 8; inventory-schema 7; ARCHITECTURE.md; PLAN.md; PRD R12; glossary; test-matrix row 6; a threat-model row and its MCP07 mapping; CHANGELOG under Changed and Security.

## Look at this first

- `internal/policy/evaluate.go` step 1. It checks `p.Defaults.UnknownTarget != Allow`, so it fails closed on `""`, `hold` or any value `Validate` would refuse.
- Targetless requests skip step 1 by design. The guard against an empty target list is M1-18's `default:bad_arguments` refusal, which is not built yet. Until then, a zero-target call to eos-mcp `daily_brief` reaches the rules.

## Deliberately unfinished

- `.claude/agents/policy-engineer.md` and `network-safety-engineer.md` still state the old default. Those are agent definitions, left for the maintainer to edit.
- PR #158's eos-mcp threat-model row names M1-37 as an open owner. Update it once both PRs have merged.
- Matrix row 6 stays `planned`. Enforcement through `serve` is M1-18/M1-19, and the tier 2 check is M1-28.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...
go build -o bin/fathomgate ./cmd/fathomgate && bin/fathomgate policy test policies/examples/*.test.yaml   # 25 passed
uv run --with pyyaml python tools/policy-lint/policy-lint policies/examples/*.yaml
uv run --with pyyaml python tools/status/render.py --check
# default unset: prod-approval.yaml with the unknown_target line removed
bin/fathomgate policy eval --policy no-default.yaml --server eos-mcp --tool get_version --class READ_OPERATIONAL --target evil.example   # deny default:unknown_target
```

## Decisions made without an ADR

- `Parse` writes `deny` into the loaded struct rather than leaving it empty, so anything that prints the loaded policy shows what is enforced. `Evaluate` does not depend on this.
- The trace note under `allow` now reads `unknown_target: allow, <CLASS> continues to rules`.

## Questions for the receiver

- Should `Validate` also warn (not refuse) on an explicit `unknown_target: allow`? **Answered by security-reviewer, 2026-09-25:** warn in policy-lint now, and in `serve` startup logging once M1-19 wires the gate. Done for policy-lint in this PR (`warn_policy` in `tests/policy_lint/lint.py`, exit status unchanged); the `serve` warning is M1-19's.

## Review round 1 (security-reviewer, approve with fixes), addressed

- M1: threat-model row and CHANGELOG Security line now name the residual: a hostname-pattern hit makes the target known (open until the ADR 0031 change lands, M1-34).
- M2: the zero-target refusal is marked open, M1-18, with eos-mcp `daily_brief` given only `tags` as the example (row, ADR 0032 point 5, policy-schema step 1).
- L1: `TestUnknownTargetDefaults` pins the YAML null forms (empty, `null`, `~`, `defaults: null`, `defaults: {}`) as deny, and loader refusals (`yes`, `true`, `false`, `""`, `hold`, a list, a duplicate key). `ALLOW` loads as `allow`: effects are case-insensitive everywhere (`ParseEffect`). Python `policy-lint` differs on two of these: it refuses `ALLOW` and PyYAML accepts a duplicate key (last wins); not changed here.
- Merged `origin/main` (M1-16); threat-model mapping conflict resolved, STATUS.md re-rendered.
