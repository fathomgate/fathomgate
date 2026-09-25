# Gate cases in policy test files (ADR 0035) ready for security review

- **Task:** M1-33 — Policy test cases that carry a profile, arguments and an inventory and run the gate path (ADR)
- **From → To:** policy-engineer → security-reviewer
- **State now:** in review
- **Branch / PR:** `feat/policy-test-gate-path` · [#197](https://github.com/fathomgate/fathomgate/pull/197) (stacked on #191, the ADR; retargeted to `main` once #191 merges)
- **Date:** 2026-09-25

## Done

- `internal/policytest` (new): the `*.test.yaml` format and runner, moved from `internal/policy/testfile.go`. Gate cases (`request.arguments` / `arguments_json`, `annotations`, `session`) run through `gate.Explain`; class-given cases run `Evaluate` as before. The ADR 0035 load errors are in `testfile.go` `Case.check` and `run.go` `RunFile`.
- `internal/configset` (new): the profile-set loader, moved out of `cmd/fathomgate/serve_policy.go`, and the inventory read (`.csv` refused, `configfile` checks). `serve`, `policy test`, and `inventory lint`/`resolve` share it.
- `internal/gate`: `Explain` returns `Decide`'s verdict plus the operator's detail. `Decide` is `Explain`'s verdict on one `decide` function.
- `cmd/fathomgate/policy.go`: `policy test --profiles`; `policy eval --profile` on the gate path, with `--arguments-json`, and `--class`/`--target` as usage errors.
- `policies/examples/{read-only,lab-open,prod-approval}.gate.test.yaml`: 112 gate cases (75, 22, 15). The 45 class-given cases are unchanged.
- Docs: policy-schema sections 5, 7 and 9; profile-schema 2.1; threat model (evidence on five rows, two new rows); CHANGELOG; ADR 0035 *Notes after acceptance*.

## Look at this first

- `internal/gate/gate.go` `Explain` and `decide`, with `explain_test.go`. This is the one deviation from the ADR: a new gate export. Check that `Decide`'s behaviour is unchanged and that nothing from `Explanation` can reach the agent.
- `internal/policytest/testfile.go` `plainYAML` and `Arguments.UnmarshalYAML`: the YAML-to-JSON path that turns a case into the bytes the gate sees (merge keys, tags, anchors, aliases and non-string keys are refused).
- `internal/policytest/run.go` messages, and `cmd/fathomgate/policy.go` output: no argument value is printed, and non-printable names are quoted (`TestNoArgumentValueInOutput`, `TestPolicyTestOutput`).

## Deliberately unfinished

- Gate cases are tier 1. Rows 3, 4 and 6 are still to be validated on the real servers in M1-28.
- `policy eval --inventory` still reads without `configfile` checks, as before (ADR 0035 notes).
- `invalid_utf8` stays in the `internal/gate` Go tests (ADR 0035 decision 6).
- Found and not fixed: inventory-schema section 3 says `version: 1` is required, but `inventory.ParseFile` refuses a `version` key (for `serve --inventory` too). This is for network-safety-engineer.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
go test ./internal/policytest ./internal/gate -run 'Repo|Gate|Load|Explain|NoArgument|Inventory|Profiles' -v
bin/fathomgate policy test -v policies/examples/read-only.gate.test.yaml
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --inventory inventory.example.yaml \
  --profile profiles/netdev-ssh-mcp.yaml --tool run_show_command \
  --arguments-json '{"host": "lab-sw-01", "command": "show version", "host": "192.0.2.99"}'
```

## Decisions made without an ADR

- `gate.Explain` is exported (recorded in ADR 0035's notes for the maintainer's review).
- The loader package is named `internal/configset`, and `inventory lint`/`resolve` use it too, with messages unchanged.

## Questions for the receiver

- Is quoting non-printable names with `strconv.QuoteToASCII` enough for CI logs, or should a gate suite's case names be restricted to printable ASCII at load?
- Should `policy eval --inventory` get the `configfile` checks now, for parity with `policy test`?
