# M1-18: internal/gate, parse to Evaluate and the one-line tool error; review round 1 addressed

- **Task:** M1-18 — internal/gate - parse, normalise, classify, resolve, Evaluate and the deny text, per ADR 0026
- **From → To:** policy-engineer → security-reviewer (then go-reviewer; design-guardian for `internal/gate/text.go` and `record.go`)
- **State now:** in review, round 2. Round 1: security H1, M1, M2, L1 to L3; Go 1 to 14; design items. This PR does not edit `docs/milestones/` or `internal/proxy`; `serve` still forwards everything (wiring is M1-19).
- **Branch / PR:** `feat/gate` · [PR #162](https://github.com/fathomgate/fathomgate/pull/162)
- **Date:** 2026-09-25

## Done

- `internal/gate`: `New(Config)`, `(*Gate).Decide(ctx, seam.CallInfo) seam.Verdict`. `CallInfo` and `Verdict` live in the leaf package `internal/gate/seam`, which imports no fathomgate package. The gate has no I/O and no state, and `policy.Evaluate` is untouched.
- Step 1: the arguments must be one JSON object in valid UTF-8, with no repeated top-level key (plain or escaped) and nothing after it. `parse_error` in the log line names the kind: `not_object`, `invalid_json`, `invalid_utf8`, `duplicate_key` or `trailing_data`.
- Step 2: the tool is looked up exactly (L2). If the profile does not list the tool and the call carries any argument, it is refused (M1). The M1-35 hook refuses unnamed and malformed arguments, with ADR 0033's texts and capped `unnamed_args` and `malformed_args` in the log (L3).
- Step 2, targets: taken exactly as sent. The rules are unchanged from round 0: hostname or IP literal, no JSON scalar, at least one target and no group selector on device tools.
- Step 3: a raise makes the call `EXEC_ARBITRARY`, and a raised tool is never downgraded (H1, N1).
- Step 4: a target is known only when the stored name matches exactly and did not come from a pattern alone.
- Effects: an allow is forwarded only when every obligation is in {`redact`, `notify`, `require_ticket`, `canary_first`}. Anything else is `cannot run`, and a name outside the vocabulary is not named to the agent (M2).
- Log line: the keys are `decision` and `session_id`; ADR 0026 has an amendment row for this. The trace is a `slog.LogValuer`.
- Example policies: the `read-only` and `prod-approval` reasons now read as the agent sees them.
- Docs: classification 4, policy-schema 5, profile-schema 2.2, ADR 0026 amendments, ARCHITECTURE, threat model (5 new rows and the unmeetable-obligation row), CHANGELOG.

## Look at this first

- `gate.go`: `classify`, then `forwardable`, then the unlisted-tool branch of `Decide`.
- Tests: `TestAnnotationRaiseNeverLowers`, `TestUnlistedToolWithArguments`, `TestObligationsAllowList`.

## Deliberately unfinished (for M1-19 and others)

- **L1.** `argumentFindings` reads `classify.Result.UnnamedArgs` and `MalformedArgs` by reflection until PR #161 is on main. Then M1-19 must replace it with direct field reads (TODO(M1-35) in `args.go`), and **must not wire the gate into the proxy before #161 is on main.** A trial merge of #161 into this branch passes every gate test, including `TestClosedArgumentListHook`. Expect conflicts in `internal/policy/types.go` (both PRs add `RuleBadArguments`; keep one), `ARCHITECTURE.md`, the threat model and policy-schema.
- **N2, for M1-19:**
  - go-sdk v1.8 `ToolAnnotations.ReadOnlyHint` is a plain `bool`. To keep "absent" apart from `false`, decode the raw `tools/list` JSON, or pass nil. Never map `false` to `&false` for every tool.
  - Recover a panic in `Decide` or in the resolver as a deny.
  - Cap the argument size before `Decide`.
  - If the proxy logs through a custom `slog` handler, add a test that an argument name with a newline stays on one line.
- Also M1-19: `Options.Gate` and the proxy `Gate` interface over `seam` types, the profile-schema 8.2 policy row, the proxy export table.
- M1-34 follow-up: the gate treats `Status == "pattern"` as not known; switch to provenance when it lands.
- M1-36: FastMCP `json.loads` a string sent for a list-typed config parameter.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...
go test -v ./internal/gate/                              # 1 skip until #161 (M1-35 hook)
go test -run XXX -bench . -benchmem ./internal/gate/     # ~5 µs/call
bin/fathomgate policy test policies/examples/*.test.yaml # 45 of 45
```

## Decisions made without an ADR

- **Case:** exact, case-sensitive match on the stored name (upstream device tables are keyed by name).
- **`_` allowed** in names.
- **The zero-target exemption follows the profile class.**
- **Group selector:** refused on device tools even alongside named targets.
- **Unknown obligation:** stops the call but is not named to the agent. Only `dry_run`, `diff` and `timed_rollback` are named.
- **Raise and existing class:** a raise keeps the class source of a call that is already `EXEC_ARBITRARY` because of its own command.

## Questions for the receiver

- Is the log cap (8 names, 64 bytes each, plus "(N more)") enough, or should the byte cap cover the whole list?
