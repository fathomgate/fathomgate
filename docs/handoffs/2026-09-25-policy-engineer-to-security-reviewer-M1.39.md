# Per-call caps, regexp-free command checks and one Decide per call, ready for security review

- **Task:** M1-39 — Bring the worst cases at the 64 KiB argument cap under the 5 ms budget (per-call caps, one Decide)
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review
- **Branch / PR:** perf/gate-per-call-caps · https://github.com/fathomgate/fathomgate/pull/185 (stacked on #183, `test/gate-overhead`)
- **Date:** 2026-09-25

## Done

- `internal/gate/args.go` `overCaps`, `countValues`: a call to a profiled tool with more than 64 commands or 256 target names and group selectors is `default:bad_arguments` before classification. The reasons are in `text.go` and name only the cap. `parse_error` is `too_many_commands` or `too_many_targets`. Profile-schema 2.4 (new), policy-schema 4 step 1.
- `internal/classify/command.go`: the anywhere blocklist regexp is replaced by `blockedWords` and `blockedPair` (`blocked`), and the shell-metacharacter regexp by `hasShellMeta`. `command_equiv_test.go` keeps both old expressions and checks the new code against them (table and fuzz). classification.md 5.3 and 5.4.
- `internal/gate/seam` `CallInfo.Counted` and `internal/gate/gate.go` `devicesTouched`: the gate subtracts targets the key has already counted. `internal/proxy/gate.go` `decideLocked` runs `Decide` once. ADR 0026 dated note.
- `internal/gate/gatetest`: the worst cases now sit at the caps, two cases fill 64 KiB past them, and `knownOverBudget` is empty.

## Look at this first

- `blocked` and `blockedPair` in `internal/classify/command.go`, against `blocklistRegexp` in `command_equiv_test.go`. The equivalence argument: after `checkBytes`, the normalised command is printable ASCII words joined by single spaces. The regexp's `(?:^|\s)…(?:\s|$)` therefore matches exactly a whole word or two consecutive whole words. The fuzzers found no difference in 60 s and 30 s.
- `countValues` in `internal/gate/args.go`: it must count at least what classify then iterates. Nested arrays are flattened as `rawValues` does, and commas are split in every target and group value, including `target_params`, which counts high.

## Deliberately unfinished

- The worst-case p99 at `GOMAXPROCS` 16 on Windows is still 7 to 13 ms. Those are collector stalls, not the call: the p99 is 1.2 to 2.1 ms at `GOMAXPROCS` 4, and 1.5 to 2.0 ms with `GOGC=off`. p99 stays logged, not enforced, for worst cases, as #183 decided. `parseArguments`' `json.Decoder` buffer growth is 244 KB of the 564 KB a 64-command call allocates. Replacing it would make collections rarer, but it is parser code and out of scope here.
- `-race` was not run locally (no C compiler); CI runs it.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && golangci-lint run ./...
make policy-test && make status-check && make licences-check && make conformance
FATHOMGATE_OVERHEAD_STRICT=1 go test -count=1 -p 1 -v -run 'TestDecideOverhead|TestDispatchOverhead' ./internal/gate/ ./internal/proxy/
go test -run '^$' -fuzz FuzzBlocklistWords -fuzztime 60s ./internal/classify/
go test -run '^$' -fuzz FuzzShellMeta -fuzztime 30s ./internal/classify/
```

## Decisions made without an ADR

- The cap values, 64 and 256, and counting targets as sent (repeats and group selectors included) rather than after de-duplication: this is stricter, and it bounds `Normalize`'s work too. These are constants, not a schema field, so no policy can raise them.
- `seam.CallInfo.Counted` is a function, not a map, so the gate cannot write to the key's set. It is recorded as an ADR 0026 note (the seam is internal), as the task brief asked.
- A cap refusal records the class the tool gets with no arguments, as a parse failure does (`EXEC_ARBITRARY` for the eos command tools).

## Questions for the receiver

- Is 256 targets per call right, given that no shipped policy allows more than 50 devices a session? Or should the cap follow the loaded policy's `max_devices` when it is lower?
- Should the start-anchored `blocklistStart` and `allowPrefix` regexps also move to word checks? They are anchored and cost little now, so I left them as they are.
