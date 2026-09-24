# T0.41: row 2 reads `passing` in the cell, its run notes and the CHANGELOG; test-engineer sign-off on the rewritten text

- **Task:** T0.41 — Reconcile matrix row 2's status word across the matrix cell, its own prose and the CHANGELOG
- **From → To:** test-engineer → docs-writer
- **State now:** in review (the board still says `open`; this PR does not edit `docs/milestones/M0.yaml`)
- **Branch / PR:** `docs/matrix-row-2-status` · PR link in the PR description (opened with this note)
- **Date:** 2026-09-24

## Done

- Word chosen: **`passing`**, one of the three legend words (`planned`, `passing`, `skipped`). No fourth word anywhere in row 2.
- Evidence: CI run [36050545450](https://github.com/joshscott13/netguard/actions/runs/36050545450), push to `main` at `51921ed` (after PR #77 and #79). Job `tier2 upa/mcp-netmiko-server (2025 era)` ([107804699914](https://github.com/joshscott13/netguard/actions/runs/36050545450/job/107804699914)): 8 passed, 0 xfailed, including `test_locked_upstream_initialises_behind_netguard` as a plain test. Job `tier2 client smoke (netdev-ssh-mcp)` ([107804699804](https://github.com/joshscott13/netguard/actions/runs/36050545450/job/107804699804)): 16 passed, 2 skipped, 1 xfailed (row 15), including `test_upstream_negotiates_2026_07_28_stateless`. `mcp-conformance` green. The run as a whole is red only on `STATUS.md is current` (board sync), not on a test.
- `docs/testing/test-matrix.md`, row 2 cell: rewritten to cite the run and the three negotiated versions.
- Same file, T0.34 run note: the locked-set bullet is now in the past tense and points to T0.39. The "Why the row is not `passing`" bullet became "Status after this run". It records that row 2 was `passing` on the two named eras (maintainer decision 2026-09-23) and that the 2024-11-05 case fell outside criterion 3 as T0.39.
- Same file, new run note "Row 2, 2026-09-24 (T0.39, T0.41)": the run, the jobs, the pins, the real servers the row rests on, and the open follow-ups T0.46 and T0.47, which do not reopen the row.
- `CHANGELOG.md` Unreleased, T0.34 line: "row 2 stays `planned`" became "was a strict xfail until T0.39 … Row 2 is `passing` (T0.41)".

**Sign-off (asked for by the Go review of PR #77):** as test-engineer I sign off on row 2's text as it stands in this PR. I checked every claim in the cell and in the new run note against the CI log of run 36050545450 and against the test source in `tests/integration/test_upa_netmiko.py` and `test_passthrough.py`. The row rests only on real upstreams:
- krisiasty/netdev-ssh-mcp v1.6.6, linux_amd64 release, sha256 `256ab497…75621`: 2026-07-28, stateless.
- upa/mcp-netmiko-server at commit `96e8ff321cc839eeb525474736439ddc2ebc795c`: 2025-11-25, stateful, with mcp 1.30.0 (hash-pinned `requirements.txt`).
- The same upa commit on its own `uv.lock`, mcp 1.6.0 (`uv sync --locked`): 2024-11-05, stateful, after one restart with `initialize` only.

The go-sdk conformance fixtures and the fake SSH device support the row but prove none of it. One limit: the tests do not read the installed mcp version. They prove 1.6.0 by its behaviour: it answers `2024-11-05`, and after `server/discover` it raises a `ValidationError`.

## Look at this first

- `docs/testing/test-matrix.md` row 2 and the run note "Row 2, 2026-09-24 (T0.39, T0.41)". Prose is yours; the facts and the status word are mine. Please change neither without a run.

## Deliberately unfinished

- `docs/milestones/M0.yaml` is not edited (brief). For the orchestrator's next board sync:
  - Move T0.41 to `in review` now and to `merged` on merge.
  - Move T0.34 and T0.39 to `validated`: row 2 ran green against its named real upstreams on `main`.
  - Exit criterion 3's `met` text ends "The 2024-11-05 startup hang is T0.39". That is stale now; suggest "The 2024-11-05 case passes too since T0.39 (PR #77, #79)".
- The orchestrator's reading in T0.41's notes is confirmed: the tick was sound, because criterion 3 names only 2025-11-25 and 2026-07-28. It no longer matters, because the 2024-11-05 case passes too.
- Not on this row: T0.46 (a launcher's grandchild outlives the restart; CI starts upa's Python directly, so it is not exercised) and T0.47 (era label after an initialize-only connect).

## Reproduce green

```sh
python tools/status/render.py --check
gh run view 36050545450 --job 107804699914 --log | grep -E "PASSED|passed"
gh run view 36050545450 --job 107804699804 --log | grep -E "2026_07_28|passed"
# locally (needs uv, Go): make build && tests/integration/upstreams/upa-mcp-netmiko-server/install.sh "$TMP/upa"
# then: cd tests && uv run --extra integration pytest integration -m "tier2 and upa_mcp_netmiko_server" -v
```

## Decisions made without an ADR

- The T0.34 run note is edited in place (tense, and a pointer forward) rather than left as written. Otherwise it still said "not `passing`" under a `passing` cell. Its measurements are unchanged.

## Questions for the receiver

- None.
