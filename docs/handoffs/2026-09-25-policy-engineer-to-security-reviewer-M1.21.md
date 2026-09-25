# M1-21: example policy cases for matrix rows 3, 4 and 6, lab-open without dry_run and diff until M3, and an example inventory with no active pattern; re-review

- **Task:** M1-21 — Example policy cases for the M1 matrix rows, and the M1 behaviour of lab-open and prod-approval
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review, round 3. Round 1 (H1, M1, L1, L2) and round 2 (H2) are addressed. This PR does not edit `docs/milestones/` or `docs/adr/`.
- **Branch / PR:** `feat/policy-m1-cases` · [PR #154](https://github.com/fathomgate/fathomgate/pull/154)
- **Date:** 2026-09-25

## Done

- `policies/examples/lab-open.yaml`:
  - `lab-writes-free` drops `obligations: [dry_run, diff]` (ADR 0026 decision 1); they return in M3.
  - The header says to list lab devices by name, not tag them by pattern (H1), and that any pattern match makes a name known, so reads reach it (H2).
  - The header also states what an M1–M2 write gets (L1), and is re-wrapped.
- `policies/examples/prod-approval.yaml`: comment only. It quotes the ADR 0026 hold line (L2).
- `inventory.example.yaml` (H2):
  - No active pattern. Every device the policies use is listed by name: core, border, firewall, fabric, access, and the lab devices including `lab-sw-01`, `lab-sw-02` and `lab-srl-01`.
  - The pattern shape stays at the end of the file, commented out, anchored at both ends and site-only, with the hazard written out: reads, loose matching, and write-unlocking tags.
  - With the previous file, `core-x.attacker.example`, `lab-x.attacker.example` and `fw-evil.example` were `allow reads-anywhere` for `READ_CONFIG` under all three policies. Now they are `deny default:unknown_target`, and `core-rtr-01` and `lab-sw-01` are still `allow`. Checked with `policy eval`.
- `TestRepoExampleInventory` checks three things:
  - the listed lab devices carry `lab`;
  - no made-up name gets `lab`;
  - none of `ghost-99`, `lab-x.attacker.example`, `core-x.attacker.example`, `fw-evil.example`, `lab-ghost-99`, `LAB-core-rtr-01`, `lab-x@core-rtr-01`, `lab-leaf-01.evil` or `core-rtr-01.attacker.example` resolves.
- `*.test.yaml`: 45 cases (read-only 12, lab-open 13, prod-approval 20).
  - The lab-open "pattern hazard" case stays (`allow lab-writes-free`). Its contrast case is now a made-up name through the shipped inventory: `READ_CONFIG`, `deny default:unknown_target`.
  - No case depended on pattern resolution: every case gives its targets explicitly.
- Docs:
  - inventory-schema section 4: patterns are optional and none are active in the example; the example shape; what the code does; the hazard for reads and writes. The `lab-` exception wording is gone.
  - PLAN resolver table row 2: optional, off in the example, with the reads warning.
  - Threat model: the row is now "Pattern-resolved target (reads and writes)", with credential exposure and the follow-ups. Row 58 has owner M1, and the unmeetable-obligation row notes lab-open.
  - CHANGELOG Security entry rewritten.

## Look at this first

- The end of `inventory.example.yaml`, then threat-model row "Pattern-resolved target (reads and writes)".

## Deliberately unfinished

- **Pattern resolution in code.** `Patterns.Resolve` still makes any match known. The follow-ups are M1-18 (target-name validation: `default:bad_arguments` for a target that is not a hostname or IP literal) and an inventory ADR on whether a pattern match alone may make a target known.
- **Runner gap.** A case takes `class` as given and cannot carry commands, so rows 3 and 4 are class-level. Closing it needs a test-file schema change and an ADR.
- **PR #152 injection inputs** are not in the suites, for the same reason. On `main` they are allowed until #152 merges.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && make policy-test && make fixtures-check && make status-check && make licences-check
bin/fathomgate policy test policies/examples/*.test.yaml                  # 45 cases, 45 passed
uv run --with pyyaml python tools/policy-lint/policy-lint policies/examples/*.yaml
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --inventory inventory.example.yaml \
  --class READ_CONFIG --target core-x.attacker.example                    # deny default:unknown_target
```

## Decisions made without an ADR

- The commented pattern example in `inventory.example.yaml` and inventory-schema section 4 sets only `site`, so copying it cannot unlock a write. It still makes a name known, and the comment says so.

## Questions for the receiver

- None.
