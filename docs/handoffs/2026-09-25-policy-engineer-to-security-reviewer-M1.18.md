# M1-18: internal/gate, parse to Evaluate and the one-line tool error, ready for security review

- **Task:** M1-18 — internal/gate - parse, normalise, classify, resolve, Evaluate and the deny text, per ADR 0026
- **From → To:** policy-engineer → security-reviewer (then go-reviewer; design-guardian for `internal/gate/text.go`)
- **State now:** in review. This PR does not edit `docs/milestones/` or `internal/proxy`; `serve` still forwards everything (wiring is M1-19).
- **Branch / PR:** `feat/gate` · [PR #162](https://github.com/fathomgate/fathomgate/pull/162)
- **Date:** 2026-09-25

## Done

- `internal/gate`: `New(Config)`, `(*Gate).Decide(ctx, CallInfo) Verdict`. Plain-data `CallInfo` and `Verdict`; no I/O, no state; `policy.Evaluate` untouched.
- Step 1: one JSON object, valid UTF-8, no repeated key (plain or escaped), nothing after it.
- Step 2: targets exactly as sent. Hostname or IP literal only. Refused: `@`, whitespace, control, non-ASCII, `:` outside zone-less IPv6, a leading `-` in any label, inet_aton spellings, JSON scalars such as `"null"`, a comma in a single-target argument, an untrimmed CSV part.
- Step 2, zero targets: a tool with a target source (profile class not `INVENTORY_READ` or `LOCAL_ADMIN`) needs a named target and no tag or group selector.
- Step 2b: hook for the closed argument list (M1-35). It goes live when `classify.Result` gains `ArgumentsOK`.
- Step 3: annotation raise (explicit `readOnlyHint: false` or `destructiveHint: true`).
- Step 4: known only on an exact stored-name match that did not come from a pattern alone.
- Effects: hold and allow-with-`dry_run`/`diff`/`timed_rollback` are not forwarded.
- Text: the fixed one-line tool error. The `default:` rules get fixed reasons.
- Log line: Info fields with protocol and era separate; the trace goes in a separate attr.
- `policy.RuleBadArguments`.
- Docs: policy-schema 5, profile-schema 2.2 (new), inventory-schema 1/7/8, classification 2/4, ARCHITECTURE, inventory package doc, CHANGELOG.

## Look at this first

- `internal/gate/args.go` `validTargetName` and `targets`, then `gate.go` `Decide` and `resolve`. Then `text.go` for the agent-facing strings.

## Deliberately unfinished

- `Options.Gate`, the proxy interface, the annotation mapping from go-sdk (its `ReadOnlyHint` is a plain `bool`), profile-schema 8.2 policy row: M1-19.
- `unnamedArguments` uses an interface assertion until PR #161 merges; then call `res.ArgumentsOK()` (TODO(M1-35)). A trial merge showed `TestClosedArgumentListHook` passes.
- `Status == "pattern"` as "not known" is the ADR 0031 interim; the follow-up adds provenance (TODO in `resolve`).
- A string sent for a list-typed config parameter is `json.loads`-ed by FastMCP; M1-36's line checks must see that list.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...
go test -v ./internal/gate/                     # 17 pass, 1 skip (M1-35 hook)
go test -run XXX -bench . -benchmem ./internal/gate/   # ~5 µs/call
go test -fuzz FuzzValidTargetName -fuzztime 20s ./internal/gate/
bin/fathomgate policy test policies/examples/*.test.yaml   # 45 of 45
```

## Decisions made without an ADR

- **Case:** exact, case-sensitive match on the stored name. `CORE-rtr-01` is `unknown` even with `core-rtr-01` listed. Upstream device tables (upa TOML, eos-mcp router list) are keyed by name, so a case variant may be another entry there or none.
- **`_` allowed** in names, because upstream inventories key by name, not only by DNS name.
- **Zero-target exemption by profile class,** so a raised `INVENTORY_READ` tool reaches the rules as `EXEC_ARBITRARY`.
- **A group selector is refused** on device tools even alongside named targets.
- **Unknown targets in denial text:** a denial by a rule under `unknown_target: allow` gets `; target not in inventory`. Held and cannot-run text does not.
- **`CallInfo` fields:** `*bool` annotations in place of `*mcp.ToolAnnotations`, and protocols beside eras. ADR 0026 left the fields to this task.

## Questions for the receiver

- Is a hostname-or-IP rule that allows `_` and uppercase tight enough for netdev-ssh-mcp's free-form `host`, given exact inventory matching behind it?
- Should the JSON-scalar refusal extend to command and config strings (M1-36), or stay target-only?
