# T0.8 is ready for review: render.py writes UTF-8 with LF on every OS

- **Task:** T0.8 — tools/status/render.py writes CRLF on Windows, so status-check reports STATUS.md stale
- **From → To:** docs-writer → go-reviewer
- **State now:** in review
- **Branch / PR:** `fix/status-render-portable` · none yet (not pushed) · issue [#10](https://github.com/joshscott13/netguard/issues/10)
- **Date:** 2026-09-23

## Done

- `tools/status/render.py`: every read uses `encoding="utf-8"`; `STATUS.md` is written with `open(..., "w", encoding="utf-8", newline="\n")`; `--check` compares `STATUS.md`'s raw bytes with the UTF-8 encoding of the rendered text (`is_current`).
- `Makefile`: `PYTHON ?= python3`; `status` and `status-check` call `$(PYTHON)`. Linux CI is unchanged. On Windows run `make status PYTHON=python`.
- `.gitattributes` (new): `STATUS.md text eol=lf` only. No repo renormalisation.
- `tests/unit/test_status_render.py` (new): renders into `tmp_path`, asserts valid UTF-8 with no `\r`, and asserts that `--check` fails on a CRLF copy.
- `CHANGELOG.md`: one line under `[Unreleased]` → `### Fixed`.

## Look at this first

- `write_status` and `is_current` in `tools/status/render.py`. The old `--check` read the file back with the same platform codec and universal newlines, so on Windows it reported `STATUS.md is current` while the file on disk was cp1252 with CRLF. Before this fix, `python tools/status/render.py` on main produced 3794 bytes, 50 CRs and cp1252 dashes, and `--check` still passed.

## Deliberately unfinished

- `.claude/commands/handoff.md`, `.claude/commands/status.md`, `.github/workflows/ci.yaml` and the render.py docstring still say `python3`. That is correct for Linux CI and macOS. The docstring now has a Windows line. The slash-command files are not docs-writer's, so they are unchanged.
- `CHANGELOG.md` has two `### Added` headings under `[Unreleased]`. That predates this task and is left for a separate docs pass.

## Reproduce green

```sh
python tools/status/render.py && git diff --stat STATUS.md     # only the handoffs table changes
python tools/status/render.py --check                           # STATUS.md is current
python -c "d=open('STATUS.md','rb').read(); d.decode('utf-8'); assert b'\r' not in d"
uv run --no-project --with pytest --with pyyaml pytest tests/unit/test_status_render.py -v
make status-check PYTHON=python                                 # where make is installed
```

## Decisions made without an ADR

- `--check` compares bytes, not text. A CRLF checkout of `STATUS.md` now fails the check instead of passing it. `.gitattributes` prevents that checkout.

## Questions for the receiver

- Should CI also run `tests/unit/test_status_render.py`, or is the `status-check` job enough?
