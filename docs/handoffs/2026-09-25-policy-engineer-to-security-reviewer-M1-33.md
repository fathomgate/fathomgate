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

- `internal/termsafe/termsafe.go` `Text` and `Unsafe`. Line feed and tab are kept on purpose, for fathomgate's own multi-line hints. Check whether any path or name from a file can still reach a message unquoted: `configfile` `what` strings, `configset`, `policytest` `run.go`.
- `internal/policytest/testfile.go` `plainScalar` and its regular expressions (`TestPlainScalars`).
- `internal/proxy/gate_surface_test.go`. It was mutation-checked by planting an `Explain` reference in a non-test proxy file.

## Deliberately unfinished

- `termsafe.Text` does not escape LF or tab (see above). This deviates from the brief's "all C0".
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

- The package name `internal/termsafe`, and keeping LF and tab in `Text`.
- The plain-scalar rule. It accepts plain strings that do not look like a number, date or time (hostnames, IPv4 and IPv6 literals, commands) and refuses `True`, `~` and `Null`. Route distinguishers such as `65000:100` must now be quoted.

## Questions for the receiver

- Is quoting at the source plus escaping everything but LF and tab at the sink enough? Or should `Text` also escape an LF that is not followed by fathomgate's own two-space hint indent?
- Should `policy eval --policy` also get the configfile checks, for symmetry with `serve`?
