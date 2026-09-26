# M1.17: capability tables for meta-tools, and a Meraki execute_api profile from source

- **Task:** M1-17, Meta-tool classification through capability tables (Meraki execute_api)
- **From → To:** policy-engineer → security-reviewer (go-reviewer and upstream-server-scout also review)
- **State now:** in review
- **Branch / PR:** `feat/capability-tables` · [PR #196](https://github.com/fathomgate/fathomgate/pull/196)
- **Date:** 2026-09-25

## Done

- **Profile fields, profile-schema §2.5.** Tool `capability_param` and `capability_table`, top-level `capabilities` (table name to capability id to class), the three names §3 planned; §3's row is gone. `internal/classify/profile.go`: `validateCapability`, `validateTable`, `validCapabilityID`, `NamedArgs`. A meta-tool must be `EXEC_ARBITRARY` with no command or config params; keys are 1 to 128 bytes of printable ASCII with no space, not JSON-looking, no two differing only in case; every table must be used.
- **Lookup, `normalize.go` `classifyCapability`.** Byte for byte. A listed id gives the table's class; anything else (unlisted, missing, `null`, non-string) gives `EXEC_ARBITRARY`; `class_source` is `capability_table` for every meta-tool call. `Reason` names the table, never the id. `CheckArguments`: `capability_param` is in the named set and must be one string (list, number, object, JSON-looking string are malformed).
- **Gate, `gate.go`.** The annotation raise tests the table's class for a meta-tool, so `readOnlyHint: false` raises a listed read; `readOnlyHint: true` (what the upstream sends) never lowers an unlisted id. `Gate.Arguments` uses `NamedArgs`, so the proxy advertises `capability_id` and drops `parameters`. No proxy change.
- **Profile `profiles/cisco-meraki-mcp-official.yaml`**, upstream `c1d00ea`: `semantic_search` `INVENTORY_READ`, `execute_api` with a 493-row `dashboard` table (`configure` → `READ_CONFIG`, `monitor`/`liveTools` → `READ_OPERATIONAL`, ten exceptions in the header). `parameters` refused (ADR 0033 §2).
- **Fixture `tests/fixtures/meraki/`**: the upstream's own `tools/list` and capability set, written by `generate.py` from its code.
- **Tests.** `internal/classify/capability_test.go` (loader table, spoofing table, `CheckArguments`, `TestMerakiCapabilityTable`, `TestMerakiToolsListFixture`, `TestMatrixRow18`, `FuzzCapabilityLookup`, `FuzzCapabilityTableKey`, 30 s each, clean); `internal/gate/capability_test.go` (row 18 under `read-only`, arguments, raw JSON escapes and duplicate keys, annotations, log line); `cmd/fathomgate` `TestEvalCapabilityTable`. Mutation: with the gate raise on `spec.Class` again, `TestCapabilityAnnotations` fails twice.
- **Docs.** profile-schema §1, §2, §2.3, §2.5, §6, §7; classification §2, §4, §9, §10; test-matrix row 18 and a run note; threat-model row "Capability-id spoofing on a meta-tool"; ADR 0010 and ADR 0033 notes after acceptance; glossary; CHANGELOG.

## Look at this first

- `internal/classify/normalize.go` `classifyCapability` and the capability branch in `Classify`, then `internal/gate/gate.go` `classify` (the `base` class for the raise).
- The ten overrides in `internal/classify/capability_test.go` `merakiOverrides` (security decision): eight `INVENTORY_READ` from `configure`, and `getOrganizationConfigurationChanges` and `getOrganizationWebhooksLogs` raised to `READ_CONFIG`.

## Deliberately unfinished

- **`parameters` is refused**, per ADR 0033 §2 (an object whose keys become Meraki SDK keyword arguments). Only 4 of 493 capabilities need no parameter, so the profile is nearly unusable until a record says how an object argument is checked. Not decided here.
- Row 18 is tier 1 only. Nothing reached a running Meraki server or the Dashboard API.
- (Round 2: the malformed capability reason is now its own text, F4.)
- `go test -race` did not run locally (no C compiler on the Windows host); CI runs it.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
go test ./internal/classify/ -run XXX -fuzz FuzzCapabilityLookup -fuzztime 30s
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --profile profiles/cisco-meraki-mcp-official.yaml --tool execute_api --arg capability_id=rebootDevice   # deny no-exec EXEC_ARBITRARY
```

## Decisions made without an ADR

- Keys are exact ids, not patterns (classification §9's old `^get` example rows are replaced). ADR 0010 says "keyed on `capability_id`"; the note after acceptance records it.
- `class_source` is `capability_table` for an unlisted id too, not `profile`.
- A meta-tool's own class must be `EXEC_ARBITRARY`, and it may not carry command or config params.
- `clipDeviceCamera` (a GET the upstream refuses by name) is left out of the table.

## Questions for the receiver

- Do the eight `INVENTORY_READ` overrides (`getDevice`, `getNetwork` and the organisation, network and device lists) belong there, given `getDevice` and `getNetwork` carry `notes` free text?
- Should the case-insensitive duplicate check in a table stay a load error, or does an upstream with two case-distinct ids need it lifted?

## Round 2 (2026-09-25): security review of PR #196 (approve, one medium)

`origin/main` merged first (#190, #191, #192, #197). `policy eval --profile` now runs the gate, so `TestEvalCapabilityTable` moved to `cmd/fathomgate/policy_capability_test.go` (main deleted `policy_args_test.go`), and it now also checks the `class_source: capability_table` line. STATUS.md was re-rendered with `render.py`. One commit per finding, no amend.

- **F1 (medium), fixed.** `getNetwork` and `getOrganizationNetworks` return `enrollmentString`, the Systems Manager enrolment secret. They are `READ_CONFIG` again and gone from `merakiOverrides`. The table now has 6 `INVENTORY_READ`, 330 `READ_CONFIG` and 157 `READ_OPERATIONAL` rows. The header no longer says those rows "carry no secret". `TestMatrixRow18` pins both.
- **F2, fixed.** The gate's raw-JSON escape cases had been decoded into plain text by an editor. They are now built from a backslash byte, and each case asserts its escape count and that it is longer than the plain form. Cases: an escaped value letter, a fully escaped id, an escaped key, key and value together, an escaped unlisted id, an escaped upper-case letter, a lone surrogate, an escaped NUL. The escape-duplicate key runs in both orders (`default:bad_arguments`).
- **F4, fixed.** When the capability argument is the only malformed one, the agent is told `the capability argument must be one string that does not parse as JSON` (`reasonMalformedCapability`). This is recorded in an ADR 0033 note and profile-schema §2.3.
- **F5, fixed** (in the F1 commit, same hunk). The profile header says a policy should attach `redact` to `READ_CONFIG`, and that Meraki JSON-keyed secrets are an M2 redaction task.
- **N1:** `decision.classify` godoc covers the table class. **N2:** profile-schema §2.5 says a write-class capability has no `ChangeSafety` payload. **N3, N4:** the spoofing row's residual adds the unchecked upstream version and SDK binding, and `semantic_search`'s untrusted spec text (MCP03).
- **New threat row (open, M2):** "Meraki `parameters` scope and JSON-keyed secret redaction", with the four ADR requirements. It says the item was moved to M2 by the maintainer 2026-09-25. `parameters` stays refused here.
- **F3, deferred to M2** in that row and the board note: the decision log line naming the matched capability key. The log line is unchanged.
- Question 1 above is answered by F1: the six remaining `INVENTORY_READ` overrides stay.
