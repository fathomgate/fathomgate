# M1.17: capability tables for meta-tools, and a Meraki execute_api profile from source

- **Task:** M1-17, Meta-tool classification through capability tables (Meraki execute_api)
- **From → To:** policy-engineer → security-reviewer (go-reviewer and upstream-server-scout also review)
- **State now:** in review
- **Branch / PR:** `feat/capability-tables` · PR opened from this branch (link in the PR list; this note is in it)
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
- The malformed-argument reason the agent sees still says "or a list of such strings", which does not hold for `capability_id`. The text is ADR 0033 §3's; left alone.
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
