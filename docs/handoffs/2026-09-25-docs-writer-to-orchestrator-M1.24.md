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
