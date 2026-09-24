# End of day 2026-09-23: three of four M0 exit criteria met; tomorrow starts with T0.39 and the T0.38 re-review

- **Task:** T0.39 — Stop netguard hanging at startup on upstreams that never answer server/discover
- **From → To:** netguard-orchestrator → joshscott13
- **State now:** open
- **Branch / PR:** none yet
- **Date:** 2026-09-23

## Done

- Exit criteria 1, 2 and 3 are met; see `STATUS.md`. Criterion 4, GoReleaser binaries on a tag, is the last.
- T0.34 (#69): upa/mcp-netmiko-server runs behind netguard in tier-2 CI at 2025-11-25, with both agent eras.
- Decisions recorded: tick criterion 3 now, and fix the startup hang with option A (probe timeout, restart, `initialize` only). No CLI flag.

## Look at this first

- **T0.38's PR**, which fixes the review findings on #68, is held for re-review. It must be re-reviewed and merged before T0.30, then T0.31 (the `--listen` flags).
- **T0.39:** write the ADR (next free number) with option A, then implement it together with T0.25.

## Deliberately unfinished

- T0.39 was tabled by the maintainer until 2026-09-24.
- T0.35 and T0.36 wait for decisions. T0.21 needs GitHub Pro or a public repo; see its note before going public.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
make status-check conformance PYTHON="uv run --with pyyaml python"   # conformance: PYTHON=python3
```

## Decisions made without an ADR

- None. T0.39 gets its ADR before any code.

## Questions for the receiver

- Criterion 4 needs a tag. Prepare `/release v0.0.1` after T0.39? Per GOVERNANCE.md, M1 ships 0.1.0, so M0 would be a `0.0.x` pre-release.
