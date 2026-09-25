# M1 is open: five records to accept, then the pipeline goes in

- **Task:** M1 — Classify + allow/deny (board: `docs/milestones/M1.yaml`)
- **From → To:** orchestrator → joshscott13
- **State now:** open; M1-01 to M1-05 in review (ADRs 0026 to 0030, proposed); 12 open, 14 blocked
- **Branch / PR:** `chore/m1-kickoff` · PR linked from the branch
- **Date:** 2026-09-25

## Done

- `docs/milestones/M1.yaml`: 31 tasks, exit criteria and validation servers copied from the M1 row of `docs/PLAN.md`; `CURRENT` is M1; `STATUS.md` re-rendered.
- Seven open M0 tasks carried with their notes (T0.35, T0.36, T0.47, T0.53, T0.54, T0.55, T0.58 → M1-10, M1-11, M1-06, M1-07, M1-08, M1-09, M1-12); their M0 rows are `dropped` with a pointer.
- Proposed ADRs 0026 (pipeline at `Proxy.dispatch`), 0027 (`serve --policy/--inventory/--profiles`; `--audit` until M4), 0028 (audit key custody, for T0.55), 0029 (remote listening with TLS, port squatting), 0030 (reload). Each lists its open questions.
- ROADMAP stage 2 marked in progress; CHANGELOG `[Unreleased]` line added.

## Look at this first

- ADR 0026 open question 1: fail closed on `dry_run`, `diff` and `timed_rollback` before M3. It decides whether `lab-open` refuses every lab write in M1, and it blocks M1-18, M1-19 and M1-21.
- ADR 0027 open question 1: keep pass-through without `--policy`, or require it. It decides the announcement's first command.

## Deliberately unfinished

- No code. The first three parallel tasks that need no record (M1-06, M1-13, M1-16) are ready to dispatch; their briefs are in the kickoff PR's report.
- `--audit` is not on the M1 board: PLAN, PRD R26 and `serve.go` put the audit chain in M4, although the M0 notes on T0.47 and T0.55 assumed M1. ADR 0027 records that.
- CLAUDE.md still says not to add proxy code outside T0.2 to T0.4. M1-24 proposes the wording; you edit CLAUDE.md.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...       # -race needs a C compiler; CI runs it
bin/fathomgate policy test policies/examples/*.test.yaml   # 25 of 25
go test -count=1 -run TestFixtureCorpus ./internal/redact/
python tools/status/render.py --check
golangci-lint run
```

## Decisions made without an ADR

- Remote listening (M1-26, M1-27) and reload (M1-25) are on the M1 board though they are not exit criteria; ADR 0029 and ADR 0030 each ask whether to park them to M2.
- Handoff file names use `M1.06` until M1-31 fixes the renderer's pattern for `M1-06`.

## Questions for the receiver

- Which of ADRs 0026 to 0030 do you accept as written, and what are your answers to their open questions?
- May the orchestrator ask upstream-server-scout to take issue #100 (upa profile) if no outside contributor has claimed it?
