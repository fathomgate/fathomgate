# Tier 1 overhead budget tests for the gate and the proxy's dispatch path, ready for Go review

- **Task:** M1-23 — Classify plus evaluate overhead under 5 ms at p99, measured in tier 1
- **From → To:** test-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** test/gate-overhead · https://github.com/fathomgate/fathomgate/pull/183
- **Date:** 2026-09-25

## Done

- `internal/gate/gatetest/overhead.go` (new, test support; nothing the binary links imports it): the typical corpus (the old `benchCorpus`, now with each case's expected decision word and rule id), six worst cases within 1 KiB of the 64 KiB argument cap, and the timing, quantile and check helpers. It also holds `RaceEnabled` (build tags), `Limit` (5 ms, or 10 times that under `-race`) and `KnownOverBudget`.
- `internal/gate/overhead_test.go`: `TestDecideOverhead` fails when the typical p99 is over the limit, or when a worst case's p50 is over it and the case is not in `KnownOverBudget`. `BenchmarkDecideOverhead` has one sub-benchmark per case. `bench_test.go` now builds `benchCorpus` from `gatetest.Typical`.
- `internal/proxy/overhead_test.go`: `TestDispatchOverhead` times `decide` + `logDecision` + `toolError` as `gated` runs them, with a real `New` over no-op in-memory upstreams, plus one case one byte over the cap. It also measures end to end, gated against pass-through; the typical p50 of the paired difference is checked.
- `.github/workflows/ci.yaml`: the Linux job has a new step, `gate overhead budget (M1-23)`, that runs both tests at 1x with `-p 1 -v` and requires `--- PASS`.
- `docs/testing/test-strategy.md` has a new section, *Overhead budget (M1-23)*, with the checks, the reasons for them, the numbers and two findings. The CHANGELOG and board are updated too.

## Look at this first

- `gatetest.CheckWorst` and the package doc of `gatetest`: a worst case fails at p50 and only logs its p99. The reason is garbage-collector pauses on Windows, 10 to 18 ms, which disappear with `GOGC=off` and on Linux. Decide whether that is a fair reading of "p99".

## Deliberately unfinished

- Neither finding is fixed. That is not this task's code (classify belongs to policy-engineer, `decideLocked` to mcp-protocol-engineer). Both are in `KnownOverBudget` and in test-strategy.md.
- No `-race` numbers were run locally: this machine has no C compiler. CI's race job passed.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
go test -count=1 -p 1 -v -run 'TestDecideOverhead|TestDispatchOverhead' ./internal/gate/ ./internal/proxy/
go test -run '^$' -bench BenchmarkDecideOverhead ./internal/gate/
```

## Decisions made without an ADR

- `KnownOverBudget` lets a named worst case pass while its p50 is over 5 ms, so CI stays green. The threshold did not move. Each entry names its finding and owner, and every run logs `KNOWN OVER BUDGET`.
- The proxy test is an internal test (`package proxy`) and repeats the three calls `gated` makes before `forward`. If `gated` changes, this test must change with it.

## Questions for the receiver

- Should the known worst cases fail the build instead (a red PR until the findings are fixed)? The brief said to report, not loosen, so this PR reports them.
- The `-race` job's time for `internal/proxy` is 59 s, against 25 s on main (101 s at 30 worst-case rounds; now 10). Most of it is the known-over worst cases at 100 to 200 ms a call under `-race`. Is that acceptable, or should those cases skip under `-race`? The 1x step holds the budget either way.

## Round 2 (Go review, request changes)

Commit `799957f`, [CI run 36189812049](https://github.com/fathomgate/fathomgate/actions/runs/36189812049), all green.

1. Worst-case p50 is enforced only with `FATHOMGATE_OVERHEAD_STRICT=1`, which is set in the `-p 1 -v` step `gate overhead budget (M1-23)` in the Linux, Windows and macOS jobs. A full parallel run logs it. Typical p99 is enforced everywhere. Locally, `go test ./...` ran green four times after the change.
2. `Proxy.decideAndRespond` (`internal/proxy/gate.go`) is a pure extract with no behaviour change. `gated` calls it and the proxy test times it. I ran the conformance recipe by hand: all 8 legs passed. Era pairs first failed because my Windows launcher used a relative binary path; they passed with absolute paths.
3. Under `-race`, worst cases get a verdict check only, and the end-to-end worst block is skipped under `-race` or `-short`. Linux `-race` job: `internal/gate` 8.4 s → 2.0 s; `internal/proxy` 59 s → 31 s (main: 25 s). macOS `-race` for `internal/proxy`: 40 s.
4. `KnownOverBudget(what, name) (finding string, ok bool)` and `Worst(known []string)` are exported; the map and `InventoryNames` are unexported. The tests load device names with `inventory.LoadFile("inventory.example.yaml")`. **This API is stable for M1-39.**
5. In the strict step, a known case whose p50 is back under budget fails with "now under budget; remove it from KnownOverBudget".

Nits are done, and `TestNotInBinary` checks that `go list -deps ./cmd/fathomgate` excludes gatetest. All three strict steps logged `KNOWN OVER BUDGET` for the same five cases, and nothing unknown was over budget. Typical p99 in the strict steps: Linux 19 µs gate / 87 µs proxy stage, macOS arm64 54 / 182 µs, Windows 527 / 740 µs (clock step 0.3 ms).

## Round 3 (Go re-check)

Commit `b124d9c`, [CI run 36190995499](https://github.com/fathomgate/fathomgate/actions/runs/36190995499), all green. origin/main is merged in and `STATUS.md` is re-rendered.

- `gatetest.TimeWorst()` is now `Strict() && !RaceEnabled`. The proxy test sends worst cases end to end only when that is true, and not under `-short`. Full-suite `internal/proxy`: Windows 50 s → 20 s, macOS 50 s → 26 s. The Linux `-race` job took 34 s for `internal/proxy` and 2.4 s for `internal/gate`.
- Stale-entry hysteresis: a known case fails as "now under budget" only when its p50 is under 0.8 × the limit (`gatetest.StaleFactor`, 4 ms). Between 4 and 5 ms it is logged as `KNOWN, NEAR BUDGET`. Over-budget detection stays at exactly 5 ms.
- `gate Decide: eos daily_brief` (3,300 targets) did not trip the strict step: its p50 was under 5 ms on all three runners, so there is no new entry. The strict steps logged the same five known cases.
