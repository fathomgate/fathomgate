# M1-21: example policy cases for matrix rows 3, 4 and 6, lab-open without dry_run and diff until M3, and lab devices listed statically; re-review

- **Task:** M1-21 — Example policy cases for the M1 matrix rows, and the M1 behaviour of lab-open and prod-approval
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review (round 2: the round 1 findings H1, M1, L1 and L2 are addressed). This PR does not edit `docs/milestones/` or `docs/adr/`.
- **Branch / PR:** `feat/policy-m1-cases` · [PR #154](https://github.com/fathomgate/fathomgate/pull/154)
- **Date:** 2026-09-25

## Done

- `policies/examples/lab-open.yaml`: `lab-writes-free` drops `obligations: [dry_run, diff]` (ADR 0026 decision 1); they return in M3. Header now says that lab devices must be listed statically, not tagged by pattern (H1), and states plainly what an M1–M2 write gets: no dry run, no diff, no rollback, and no audit event until M4 (L1).
- `policies/examples/prod-approval.yaml`: comment only, quoting the ADR 0026 hold line `fathomgate held <server>.<tool>: rule prod-core-needs-approval (class WRITE_CONFIG): ...` (L2).
- `inventory.example.yaml` (H1): `^lab-` sets only `site: lab`; `lab-sw-01`, `lab-sw-02`, `lab-srl-01` are listed statically with tag `lab`. Warnings at the top and on both patterns. `TestRepoExampleInventory` checks that the static lab devices carry the `lab` tag and that `lab-ghost-99`, `LAB-core-rtr-01`, `lab-x@core-rtr-01`, `lab-leaf-01.evil` and `Lab-Sw-01x` do not. It fails with the old pattern: checked, then reverted.
- `*.test.yaml`: 45 cases (read-only 12, lab-open 13, prod-approval 20). Rows 3, 4, 6 in all three. lab-open row 6 now uses `ghost-99`, which the example inventory can actually produce as unknown (M1). New "pattern hazard" case: `allow lab-writes-free`, with a comment explaining it. It is paired with the same name through the shipped inventory: `deny not-lab` (H1.3).
- Docs: inventory-schema section 4 (example, what the code does, the warning); policy-schema section 9; threat model: a new row, row 58 moved to M1, and the unmeetable-obligation row; CHANGELOG Added, Security, Changed.

## Look at this first

- `inventory.example.yaml`, then the new threat-model row "Pattern-resolved target satisfies `device_tags` for writes".

## Deliberately unfinished

- **Pattern resolution in code.** `Patterns.Resolve` still makes any match known. inventory-schema section 4 said a tags-only pattern never does. The spec now describes the code; changing the code is for M1-18 and an inventory ADR. The `^lab-` site-only pattern still makes any `lab-` name known, so a read of it is not stopped by the unknown-target default.
- **Runner gap.** A case takes `class` as given, and it has no arguments or commands. So rows 3 and 4 are class-level. The profile half is covered by tier 1 and `policy eval --profile`. Closing it is a test-file schema change and needs an ADR.
- **PR #152 injection inputs** are not in the suites, for the same reason. On `main` they are still `allow READ_OPERATIONAL reads-anywhere` until #152 merges.
- `docs/PLAN.md` row 2 of the resolver table still says `^lab-` → tag `lab`. `CLAUDE.md` says 43 cases, and it is now 45. Both are the maintainer's to edit.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && make policy-test && make fixtures-check && make status-check && make licences-check
bin/fathomgate policy test policies/examples/*.test.yaml                  # 45 cases, 45 passed
uv run --with pyyaml python tools/policy-lint/policy-lint policies/examples/*.yaml
bin/fathomgate policy eval --policy policies/examples/lab-open.yaml --inventory inventory.example.yaml \
  --class WRITE_CONFIG --target 'lab-x@core-rtr-01'                       # deny not-lab
```

## Decisions made without an ADR

- The `^lab-` pattern keeps `site: lab` rather than being removed. No rule matches on site. The cost is that `lab-` names stay known for reads.
- `^core-|^border-` → role `core` stays. In the shipped examples a role only ever leads to `hold`, never to `allow`, and the comment says so.

## Questions for the receiver

- Should `^lab-` go entirely, so that a made-up `lab-` name is unknown for reads too?
