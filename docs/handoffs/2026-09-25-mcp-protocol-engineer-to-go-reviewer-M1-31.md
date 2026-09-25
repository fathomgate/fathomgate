# M1-31: the status renderer reads handoff notes named with a hyphenated task id (this note is one)

- **Task:** M1-31 — Let the status renderer read handoff notes whose task id has a hyphen (M1-06)
- **From → To:** mcp-protocol-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** fix/status-hyphen-ids · https://github.com/fathomgate/fathomgate/pull/190
- **Date:** 2026-09-25

## Done

- `tools/status/render.py`: new `parse_handoff_name`. It tries `HANDOFF_HYPHEN_RE` first: a task id `M<n>-<n>` or `T<n>-<n>` that ends the file name, optionally followed by `-round<n>` (the task shown is the id without the suffix). Otherwise it falls back to the unchanged `HANDOFF_RE` (last hyphen-free part), so dot-form names (`M1.06`, `T0.51`) parse as before. `latest_handoffs` calls it.
- `tests/unit/test_status_render.py`: a table of hyphen, round-suffix and dot-form names plus `README.md` and `_template.md` (not notes); a test that every note on disk parses exactly as the old pattern parsed it; a test that `latest_handoffs` lists a hyphen-id note with the right receiver and task.
- `docs/handoffs/README.md`: the file name ends with the board's id (`M1-06`), `-round<n>` is the one allowed suffix, and older dot-form names stay as written.
- Board: M1-31 is `in review`.

## Look at this first

- `HANDOFF_HYPHEN_RE` in `tools/status/render.py`. The `to` group is greedy, so `...-to-go-reviewer-M1-06.md` gives receiver `go-reviewer` and task `M1-06`. The old pattern gave `go-reviewer-M1` and `06`.

## Deliberately unfinished

- Dot-form names that have a suffix (`...-M1.36-round2.md`) still render the suffix (`round2`) as the task. Fixing that would change how existing notes render, and the brief was to keep `--check` output identical for them.
- The orchestrator's M1 kickoff note still says to use `M1.06` until this merges. Handoff notes stay as written.

## Reproduce green

```sh
cd tests && uv run pytest unit/test_status_render.py unit/test_status_issues.py -q   # 40 passed
uv run --with pyyaml python tools/status/render.py --check                             # STATUS.md is current
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make licences-check
```

## Decisions made without an ADR

- The hyphen form accepts only the `M` and `T` prefixes and only a `-round<n>` suffix. Anything else falls back to the old pattern, so a note never disappears from the render. At worst its columns come out as they did before this change.

## Questions for the receiver

- Should `render.py --check` also fail on a note name that neither pattern reads? Today such a note is skipped without a warning, and that has not changed.

## Round 2 (Go review approved, fixes)

Commit `6d8e8a3`.

- `test_no_note_before_m1_31_is_read_as_hyphen_form` replaces the vacuous on-disk comparison. It checks that every name matching `HANDOFF_HYPHEN_RE` is dated 2026-09-25 or later.
- `handoff_order` is the new sort key for `latest_handoffs`: (date, name without `-round<n>`, round), with the base note counting as round 1. It gives the same order for the notes on disk today. `test_latest_handoffs_lists_rounds_in_order` covers both forms and round10 after round2; the plain name sort fails it.
- Board: owner is mcp-protocol-engineer, reviewers are [go-reviewer], and the note date is 2026-09-25. The follow-up to have `--check` warn on unreadable names is recorded in the M1-31 notes.
