# T0.9 ready for review: nightly-clab.yaml was invalid YAML, now parses and stays skipped

- **Task:** T0.9 — nightly-clab.yaml fails with a workflow file error on every push to main
- **From → To:** release-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** `ci/nightly-clab-parse` (from `c43d02e`, not pushed) · none yet · issue [#11](https://github.com/joshscott13/netguard/issues/11)
- **Date:** 2026-09-23

## Done

- Root cause: line 40 of `.github/workflows/nightly-clab.yaml` was a plain scalar `run: echo "TODO(M3): containerlab destroy ..."`. The `: ` after `TODO(M3)` starts a mapping, so the file is not valid YAML. GitHub rejects it, shows the path instead of the workflow `name`, and records a 0s failed run with no jobs for every push. None of the suspects in the brief caused it: the `vars` in the job-level `if`, the label set, `go-version-file`, a BOM, the cron comment and the parentheses in `name` are all fine.
- Evidence: `actionlint` v1.7.12 on `c43d02e` reported `nightly-clab.yaml:40:27: could not parse as YAML: mapping values are not allowed in this context [syntax-check]`. PyYAML gives the same error at line 40, column 28. From the API, runs have `name: ".github/workflows/nightly-clab.yaml"`, `jobs.total_count: 0` and a check suite with 0 check runs. The API does not show the error text, and the repo is private, so I could not scrape the run page.
- Fix: the destroy step now uses `run: |`, like the other two TODO steps, with a comment explaining why. The trigger, `runs-on: [self-hosted, clab]`, the `if: ${{ vars.NETGUARD_CLAB_ENABLED == 'true' }}` and the TODO(M3) skeleton are unchanged.
- Added `.github/actionlint.yaml` to declare the custom `clab` runner label. Without it, actionlint reports `runner-label` once the file parses.
- Added one line to `CHANGELOG.md` `[Unreleased]` under a new `### Fixed` section. T0.9 is now `in review` in `docs/milestones/M0.yaml`, and `STATUS.md` is re-rendered.

## Look at this first

- `.github/workflows/nightly-clab.yaml` lines 38–44, the destroy step. That is the only change to the workflow.

## Deliberately unfinished

- actionlint is not wired into `ci.yaml`. Adding a CI lint step is a separate change and a candidate follow-up.
- Not confirmed on GitHub yet. The proof after merge: `gh run list --workflow nightly-clab.yaml` shows no new failed `push` run for the merge commit, and the Actions tab shows the workflow as `nightly-clab (tier 3, placeholder)` instead of its path.

## Reproduce green

```sh
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/*.yaml   # exit 0, no output
git status --porcelain                                                               # go.mod untouched
PYTHONUTF8=1 python tools/status/render.py --check
```

## Decisions made without an ADR

- Added `.github/actionlint.yaml`, a linter config with no runtime effect.

## Questions for the receiver

- Should an actionlint step be added to `ci.yaml` as a follow-up, so a broken workflow file fails a PR instead of `main`?
