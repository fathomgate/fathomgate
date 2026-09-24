# T0.4 merged before review: post-merge review of the MCP conformance job, and the baseline for exit criterion 1

- **Task:** T0.4 — Conformance suite in CI against the client-facing side; make conformance target
- **From → To:** test-engineer → go-reviewer
- **State now:** merged
- **Branch / PR:** ci/conformance-suite · https://github.com/joshscott13/netguard/pull/44
- **Date:** 2026-09-23

## Done

- `make conformance` and the CI job `mcp-conformance` run `@modelcontextprotocol/conformance` 0.2.0-alpha.11 (locked in `tests/conformance/package-lock.json`) with `--requirements 2025-11-25` and `2026-07-28` against the real `netguard serve`. The upstream is go-sdk v1.8.0's `conformance/everything-server`; `go.mod` is unchanged.
- The suite is HTTP-only, so `tests/conformance/relay.py` (stdlib) fronts stdio. A control leg without netguard shows the relay is transparent: 2025 passes 30/30; 2026 fails only 12 HTTP-transport checks.
- netguard leg: 11/30 scenarios clean in 2025, 16/37 in 2026. Every other scored check has its own entry in `tests/conformance/baseline/` with a reason. A new failure fails the run, and so does a baseline entry that starts passing.

## Look at this first

- `tests/conformance/relay.py`: it should make exactly two rewrites, request ids and the `conf.` prefix on `tools/call` only. Then the baseline reasons, the Makefile file targets, and the job's `name:` and trigger (it becomes a required check, T0.21).

## Deliberately unfinished

- Findings split out as T0.17 (progress not relayed, §8.4), T0.18 (strict -32602 on retries, §8.2), T0.19 (no 2025-era upstream behind netguard).
- Exit criterion 1 stays unticked: the maintainer decides whether "passes with a reasoned baseline" meets it.
- Matrix rows 1 and 2 are not validated: the run used a fixture, not the named real servers.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
make status-check actionlint conformance PYTHON="uv run --with pyyaml python"
(cd tests && uv run --extra dev pytest unit -q)
```

## Decisions made without an ADR

- The pre-release suite version is pinned because it is the only one with the 2026-07-28 requirement set, and go-sdk v1.8.0 pins the same version.

## Questions for the receiver

- Is the Python relay acceptable as test-only code, or should the suite get an in-process Go HTTP front instead?
