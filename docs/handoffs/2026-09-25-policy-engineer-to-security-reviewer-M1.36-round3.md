# M1-36 round 3: fixes for the round-2 re-review of PR #170 (autocommand, comment separator, Junos word trim)

- **Task:** M1-36: Config lines that leave the configure session make a write EXEC_ARBITRARY
- **From → To:** policy-engineer → security-reviewer (the tier-2 section is for test-engineer)
- **State now:** in review
- **Branch / PR:** feat/classify-config-escape · https://github.com/fathomgate/fathomgate/pull/170
- **Date:** 2026-09-25

## Done

- R2-H1: in the CLI dialect, a line fails `exec-config` when any word, with punctuation trimmed from both ends, is a prefix of `autocommand` at least 5 characters long. Tests: `line vty 0 15` then ` autocommand reload`; `username netops autocommand reload`; `autoc`; a quoted `"autocommand"`. These run in `TestSecurityConfigSessionEscape` and, under lab-open, in gate `TestConfigSessionEscape`. `auto-cost`, `speed auto` and `autocommand-options` still pass (`TestConfigLinesThatStayWrites`).
- R2-M1: the `;` check now runs before blank and `!` comment lines are passed, so `! x ; reload` and `!;reload` fail with `separator`.
- R2-L1: Junos set words are trimmed of every character outside `[a-z0-9-]` at both ends, so `set event-options\ x` and `(scripts)` fail. The one-letter false positives (`description e`, `policy-statement s`) are tested and recorded in spec 11.3 as an accepted cost.
- Threat model: the session-escape row now lists the round-2 fixes, keeps Junos text-format abbreviations open pending tier 2, and marks IOS `menu ... command` and EOS `username ... shell` as accepted. Spec 11.5 says the same.

## Look at this first

- `checkCLIConfigLine` in `internal/classify/config.go`, for the order of checks: separator, then the comment return, then autocommand, then the first word.

## Deliberately unfinished

- Tier 2 for test-engineer, recorded in M1-28's board notes:
  - cEOS: does a line after `end` escape the session within one eAPI call? Do `clock set`, `watch` and `terminal` work from configuration mode? Does `alias hn reload now` followed by `hn` run the reload?
  - vMX or cRPD: is a text load of `system { scr { op { file x; } } }` refused? If it is accepted, classify must tokenise Junos text payloads and apply the set-format prefix test (spec 11.3).
- The EOS `push_config` top-level allow-list is still open.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...        # -race needs cgo; not on this Windows host
~/go/bin/golangci-lint run ./...                       # 0 issues
go build -o bin/fathomgate.exe ./cmd/fathomgate
bin/fathomgate.exe policy test policies/examples/lab-open.test.yaml policies/examples/prod-approval.test.yaml policies/examples/read-only.test.yaml   # 45 cases, 45 passed
uv run --with pyyaml python tools/licences/spdx.py && uv run --with pyyaml python tools/status/render.py --check
```

## Decisions made without an ADR

- The autocommand check applies to the CLI dialect only. On Junos, `autocommand` is not a configuration statement.

## Questions for the receiver

- None.
