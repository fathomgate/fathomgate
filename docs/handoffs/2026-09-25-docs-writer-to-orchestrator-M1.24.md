# M1-07, M1-08 and M1-24 in review: threat-model rows, Fathomgate in prose, M1 matrix and specs reconciled with main

- **Task:** M1-07, M1-08 and M1-24 (M1-24 — Reconcile the M1 test-matrix rows and specs with the code and PLAN)
- **From → To:** docs-writer → orchestrator, to route the reviews: security-reviewer (M1-07), design-guardian (M1-08), policy-engineer and test-engineer (M1-24)
- **State now:** in review, all three
- **Branch / PR:** `docs/m1-docs-reconcile` · [PR #194](https://github.com/fathomgate/fathomgate/pull/194)
- **Date:** 2026-09-25

## Done

- **M1-07** (`docs/security/threat-model.md`, `SECURITY.md`): seven rows from the PR #108 review and PR #111 N5, each with status and owner. Open: upstream text inside tool results (mcp-protocol-engineer, M2 content-block labels), tool descriptions changed by an upstream release (mcp-protocol-engineer, M2 re-pin with row 16), no secret scanner in CI (release-engineer with test-engineer), an upstream opening Fathomgate's own process on Windows (mcp-protocol-engineer). Mitigated: upstream `instructions` (T0.51), whitespace variants (M1-16). Accepted: a readable upstream obfuscation key (install.md guidance). The leading-dash row was already routed (M1-14). OWASP mapping updated; SECURITY.md parser-differential row closed by M1-18 and M1-19.
- **M1-08**: 506 prose uses of `fathomgate` in Markdown became Fathomgate (scanner skips code spans, fences, URLs, paths and quoted runtime text); conformance legs named `fathomgate` are in mono. Exempt as CLAUDE.md says, plus STATUS.md (rendered) and ADR 0019 (the rename record).
- **M1-24**: test-matrix rows 3 to 6 and the coverage tables; classification, policy-schema, profile-schema, inventory-schema, audit and approval examples, ARCHITECTURE, glossary. Rows 3, 4 and 6 stay `planned` (M1-28).

## Look at this first

- `docs/testing/test-matrix.md` rows 5 and 6: the split between M1 and M2 (row 5) and M1 and M4 (row 6).
- `docs/security/threat-model.md`, the seven rows above `## OWASP MCP Top 10 mapping`.

## Deliberately unfinished

- No Go changes. `internal/classify/normalize.go` still says `SourceAnnotationRaise` is "Reserved for M1-18" and that `Classify` emits four sources; `internal/gate` emits `annotation_raise` since M1-18. A comment fix for policy-engineer.
- CLAUDE.md is the maintainer's. Proposed replacement for "`fathomgate serve` lands across T0.2–T0.4 on the M0 board; don't add proxy code outside those tasks.": "Proxy code (`internal/proxy`, `cmd/fathomgate/serve*.go` and `listen*.go`) changes only under a board task whose package is `internal/proxy` or `cmd/fathomgate`; a change at the agent or upstream boundary needs an ADR first (ADR 0012, ADR 0026)."
- Board titles keep lower-case prose (M1-06, M1-20, M1-22), so STATUS.md does too.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
```

The M1-08 scanner was a scratch script and is not committed.

## Decisions made without an ADR

- Row 5 keeps its number and carries both halves in one row, so "row 5" references stay valid. Its M1 tier 2 half (upa `send_command_and_get_output`, eos-mcp `run_command`) is in no board task: M1-28 covers rows 3, 4 and 6.
- New threat-model owners are named by agent and milestone, not by board task, because there is no M2 board yet.

## Questions for the receiver

- The fallback classifier (PLAN M1 deliverables; classification section 3) is not implemented, and M1-15 asks for fallback tests from brief 02. Implement section 3 in M1, or change M1-15 and the PLAN row to what the code does (unlisted tool with arguments is `default:bad_arguments`, without is `EXEC_ARBITRARY`)?
- Add row 5's M1 tier 2 half to M1-28, or a new task? And pull the gitleaks repository and fixture scan into M1 as a task?
- ADR 0020 (lines 51, 56, 68, 127) names `netguard policy test`, `netguard inventory sync`, `netguard audit verify` and `./cmd/netguard`. It is after ADR 0019 in number but outside CLAUDE.md's exempt range. Rewrite to `fathomgate`, or add it to the exempt list?

## Round 2 (2026-09-25): maintainer decisions and the security, design and test reviews

- **ADR 0036** (accepted 2026-09-25, `docs/adr/0036-no-fallback-classifier.md`): no fallback classifier; supersedes that half of ADR 0010 (pointer line in 0010). classification.md intro, section 2 step 2 and section 3 (now "Tools with no profile entry") and the `frobnicate` row; PLAN classification paragraph and M1 row; ADR 0020 M1 row and profile-library row; ADR 0026 steps 2 and 3; ADR 0027 decision 3 note; ADR 0033 "No profile"; ARCHITECTURE; new MCP03 threat-model row for upstream-controlled tool names (mitigated).
- ADR 0020 names `fathomgate` commands. PLAN and test-strategy tier 2: pytest over stdio, with a dated note in PLAN. CLAUDE.md and AGENTS.md: proxy-code rule, repo-map line and no-profile bullet. The serve bullet was already current on main.
- Security: threat-model rows 113 to 115 and 117 to 119 as the review asked; row 118 points at M1-42; SECURITY.md rows for the Windows process and results injection.
- Design: "denied by rule" wording, the ADR 0026 hold example, "Fathomgate process", and "Fathomgate's" in the M1-07 note.
- Test: rows 4 to 6, profile-schema 2.2 and 8.2, M1-24 matrix `[3, 4, 5, 6]`, M1-28 note "reads, config reads and exec". Row statuses and M1-28's matrix unchanged.
- Row 6: the M1-22 eos-mcp `default:unknown_target` cases in tier 2 are reads; `WRITE_CONFIG` to an unknown host is covered in tier 1 only (`read-only.test.yaml`). A tier 2 write case would be M1-28's to add.
- Expected merge conflicts: PR #196 (classification.md section 2 step 1 is next to step 2; ADR 0010 header), PR #195 (row 6 and the M1-28 note), PR #193 (classification.md).
- Threat-model row "Server without a profile under `--policy`" now names `TestFallbackBrief02Gate` (`internal/gate`, PR #193, open when this was written) and ADR 0036.

## Round 3 (2026-09-25): the security re-check's four lows

- L1: the "Upstream-controlled tool names choose the class" row carries the open residual (a changed implementation behind a profiled name keeps its class; M2 pinning catches it only when the advertised text changes).
- L2: ADR 0036 *Negative* and the no-profile row name the zero-target residual (a policy that allows `EXEC_ARBITRARY` without roles or tags forwards an unprofiled no-argument call).
- L3: `TestFallbackBrief02Gate` is cited as "PR #193, pending"; #193 was open at push.
- L4: CLAUDE.md's mandatory security-review list adds `internal/gate` and `internal/proxy`; the proxy rule in CLAUDE.md and AGENTS.md says proxy changes get a security review.
- ADR 0036's example is a gate case in `policies/examples/read-only.gate.test.yaml` (`netdev-ssh-mcp` tool `show_command` with `command` gets `default:bad_arguments`, class `EXEC_ARBITRARY`, source `fallback`); policy-schema section 9 counts 76 gate cases.
- New board task M1-43 (open, mcp-protocol-engineer): tier 1 test that a hostile upstream `Instructions` string never reaches the agent, both eras. The threat-model row points at it.
