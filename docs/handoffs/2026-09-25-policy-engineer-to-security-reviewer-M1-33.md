# Follow-up to the PR #197 security review ready for re-review

- **Task:** M1-33 — Policy test cases that carry a profile, arguments and an inventory and run the gate path (ADR)
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review (stays in review until this PR merges)
- **Branch / PR:** `fix/policytest-review` · [#199](https://github.com/fathomgate/fathomgate/pull/199)
- **Date:** 2026-09-25

## Done

- **L1:** new package `internal/termsafe`: `Quote`, `QuoteEach` and `List`, shared by the CLI and `internal/policytest`, plus `Text`. `fail` and `failTo` print every error through `Text`. Paths are quoted where they enter a message (`internal/policytest/run.go`, `internal/configset`). `internal/configfile` drops the raw path from OS errors (`withoutPath`).
- **L2:** the threat row is reworded and now covers L1.
- **L3:**
  - `readCapped` (16 MiB) for the test file and its policy;
  - `noAnchors` over the whole test file before decoding;
  - `MaxCaseName` of 256 bytes.
- **L4:** `plainScalar` in `internal/policytest/testfile.go`.
- **N3:** `logRecord.has` and `absent`.
- **N4:** `configset.ProfileFileAt`, and `policy eval --inventory` now reads through `configset.ReadInventory`.
- **Guards for `gate.Explain`** (accepted by the maintainer; recorded in ADR 0035): `internal/proxy` `TestGateSurface`, and the extended `TestExplainMatchesDecide` plus `FuzzExplainMatchesDecide`.
- **N1, N2, weaker gate cases and Go notes:** as listed in the PR body. Gate cases now total 113.

## Look at this first

- `internal/termsafe/termsafe.go` `Text` and `Unsafe`. (Round 1 kept line feed and tab; round 2 escapes them too, see below.) Check whether any path or name from a file can still reach a message unquoted: `configfile` `what` strings, `configset`, `policytest` `run.go`.
- `internal/policytest/testfile.go` `plainScalar` and its regular expressions (`TestPlainScalars`).
- `internal/proxy/gate_surface_test.go`. It was mutation-checked by planting an `Explain` reference in a non-test proxy file.

## Deliberately unfinished

- (Round 1) `termsafe.Text` did not escape LF or tab. Superseded in round 2: it escapes every C0 control, and configfile's fix commands travel as `configfile.Hint`.
- N2 is covered by a unit test (`TestInventoryPath`), not by a shipped suite. A repo checkout can fail the configfile check on Windows.
- Accepted residual (new threat row): the test file, its policy, and `policy eval --policy` are read without configfile checks. They configure a check, not an enforcement.
- inventory-schema section 3 still says `version: 1` is required while the decoder refuses a `version` key. This is for network-safety-engineer; it is unchanged here.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
go test ./internal/termsafe ./internal/configset ./internal/policytest ./internal/gate ./internal/proxy -run 'Text|Quote|Profile|Inventory|Plain|Caps|Absent|NoArgument|Explain|GateSurface' -v
go test ./internal/gate -run XXX -fuzz FuzzExplainMatchesDecide -fuzztime 30s
go test ./cmd/fathomgate -run 'FailSink|FailEscapes|ReadsLikeServe|PolicyEval' -v
```

## Decisions made without an ADR

- The package name `internal/termsafe`. (Round 1 also kept LF and tab in `Text`; round 2 reversed that.)
- The plain-scalar rule. It accepts plain strings that do not look like a number, date or time (hostnames, IPv4 literals, commands) and refuses `True`, `~` and `Null`. Correction (round 2): not every IPv6 literal passes. One made only of decimal groups and single colons, such as `2001:0:0:0:0:0:0:1`, looks sexagesimal and must be quoted; `2001:db8::1`, `fe80::1` and `::1` pass. Route distinguishers such as `65000:100` and all-digit MAC addresses must be quoted too.

## Questions for the receiver

- (Round 1, answered by R1 in round 2: the sink now escapes LF and tab as well.)
- Should `policy eval --policy` also get the configfile checks, for symmetry with `serve`?

## Round 2: re-review of PR #199 (approved; no critical, high or medium)

- **Merge.** `origin/main` merged via `FETCH_HEAD` (#196 and M1-17's capability tables). `TestEvalCapabilityTable` from main now copies the Meraki profile into a `configDir` and expects the aligned `eval` labels.
- **R1: a line break a parser echoes forged a line.**
  - At the sources: `internal/inventory/patterns.go` reports `roles[i] <quoted match>: not a valid regular expression (<syntax code>)` and drops the regexp error's echo of the expression. `internal/classify/profile.go` quotes the server key and tool names with `termsafe.Quote`.
  - At the sink: `termsafe.Text` now escapes line feed and tab too. `internal/configfile` returns its icacls commands apart from the message (`configfile.Hint`). The CLI's one printer, `printError` (used by `fail`, `failTo`, `serve` and `inventory lint`), prints the escaped message and then each hint line, escaped.
  - Tests: `TestNoForgedLines` sends the reviewer's `(` plus `3 cases, 3 passed, 0 failed` block scalar through the inline and path inventory patterns, `inventory lint`, the profile server key and tool name, and the policy through both `policy test` and `policy eval`. It asserts that each case reaches its intended error and that no output line starts with the forged text. `TestFailSink` checks a real configfile refusal: one message line, then only `  icacls` lines. The Windows configfile tests read the commands from `Hint`.
- **R2.** One sentence on inventory permissions sits beside the `policy eval --inventory` examples in README.md and CLAUDE.md.
- **R3.**
  - A number passes unquoted only when `encoding/json` writes it back as exactly its text. This is stricter than FormatInt/FormatFloat, because it also refuses floats JSON would print with an exponent, such as `0.0000001`.
  - A plain string that looks like a number, date or time now gets "looks like a number, date or time; quote it".
  - `TestPlainScalars` adds `1.0`, `2.50`, `-0`, a long pi, `100000000000000000000.0`, `0.0000001`, `65000:100`, an all-digit MAC and `12:30`.
  - The IPv6 claim above is corrected.
- **Item 4.** `TestGateSurface` walks subdirectories, refuses any identifier containing `Explain`, and refuses `MethodByName`. It was mutation-checked with a planted subdirectory.
- **Threat model.** "A policy test suite as injection text" is mitigated, including R1. "A policy test file that expands without bound" is mitigated.
- **Docs.** policy-schema 7.1 and 7.4, the CHANGELOG, and ADR 0035 notes after acceptance (a round-2 table).
