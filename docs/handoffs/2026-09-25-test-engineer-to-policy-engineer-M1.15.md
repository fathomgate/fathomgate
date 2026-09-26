# Fallback-classification tests for every other surveyed tool, at the Classify and gate levels

- **Task:** M1-15 — Tier 1 fallback-classification tests for every other surveyed tool in brief 02
- **From → To:** test-engineer → policy-engineer
- **State now:** in review
- **Branch / PR:** test/m1-15-fallback-classes · https://github.com/fathomgate/fathomgate/pull/193
- **Date:** 2026-09-25

## Done (as of round 2)

- **The table:** `internal/classify/classifytest/brief02.go` (new, test only; `TestNotInBinary` keeps it out of `cmd/fathomgate`).
  - It has one row per tool that brief 02 names on a server with no shipped profile: 138 tools on 14 servers. That is mcp-telecom 55, mcfortigate 17, pyATS 15, netbox-mcp-rw 9, network-discovery 8, Catalyst Center 7, clab 6, NetBox 4, Palo-MCP 4, cdot65 pan-os 4, fortigate-mcp 4, SD-WAN 3, scrapli 1 and Meraki `semantic_search` 1.
  - The class brief 02 gives each tool is kept as documentation only: section 2(c) first, then Part 1, and the stricter of the two where they disagree.
  - `NeverDowngrade` names the section 8 tools.
  - Some names and arguments are representative, and the rows say so: one name per fortigate-mcp family, the Palo-MCP arguments, and the network-discovery arguments.
- **What happens to these calls:** every row is `EXEC_ARBITRARY`, `class_source: fallback`, never downgraded and never forwarded.
  - Calls with arguments (113 rows) are denied `default:bad_arguments`: under the empty profile every argument is unnamed (ADR 0033).
  - Calls with none (25 rows, for example the cdot65 `retrieve_*` tools and the SD-WAN three) reach the rules as `EXEC_ARBITRARY` with zero targets and are denied by `no-exec` in all three example policies.
- **Tests:**
  - `internal/classify/fallback_brief02_test.go` (package `classify_test`). `TestFallbackBrief02` runs every row through `Classify` three ways: with no profile, with the empty profile `serve` builds, and with the `server.tool` name. Each must be `EXEC_ARBITRARY`/`fallback`, with every argument unnamed under the empty profile. `TestFallbackBrief02Table` guards the table: no listed server may have a shipped profile, no row repeats, there is no Meraki `execute_api` row, and the `NeverDowngrade` names exist.
  - `internal/gate/fallback_brief02_test.go`. `TestFallbackBrief02Gate` runs every row through `Decide` with the empty profile, under read-only, lab-open and prod-approval. It asserts `EXEC_ARBITRARY`, `fallback`, `!Forward`, deny, no targets and the rule exactly: `default:bad_arguments` with arguments, `no-exec` without.
  - `cmd/fathomgate/serve_policy_test.go` `TestNoProfileServerDeniesArguments` now asserts `Forward`, the effect, the rule and the source for both calls.
- **Docs:** classification.md section 10 and a CHANGELOG `Unreleased` entry.

## Round 2 (security approve with M1, L1 and L2; maintainer decision on section 3)

- **Maintainer decision (2026-09-25):** the section 3 fallback classifier will not be built. The ADR is in PR #194. The round 1 design findings about section 3 (15 tools less strict than brief 02, section 8 not enforced without a profile) are now moot; they are kept below for the ADR's record.
- **M1:** the gate-level test is added. The rows moved into the shared `classifytest` table so the classify test and the gate test use the same rows. `TestNoProfileServerDeniesArguments` is tightened.
- **L1:** `brief02Known` and its `t.Skipf` are deleted. A weaker class now fails.
- **Strictness order:** it is replaced by `Class == EXEC_ARBITRARY` on every row. The comments say the fallback never downgrades.
- **L2:** the wording is fixed here, on the board and in the PR description.
- **Go nits:**
  - `NeverDowngrade` is a separate name set, so the rows no longer end in a positional bool.
  - `slices.Equal` replaces `reflect.DeepEqual`.
  - The `//nolint:misspell` lines are kept (they are upstream tool names).
- **Worth knowing:** under a policy with a catch-all `allow` (the test's `everything` rule), a call with no arguments to an unprofiled tool is forwarded. The empty profile refuses arguments, not tools. All three example policies deny it with `no-exec`.

## Look at this first

- `TestFallbackBrief02Gate`. It is the path `serve` takes, and the only place that checks the decision.

## Deliberately unfinished

- **Surfaces the brief names without tool names, which cannot be tested:**
  - CloudVision.
  - clab FloSch62.
  - The other 113 Palo-MCP tools.
  - The other 389 fortigate-mcp tools.
  - The other 36 SD-WAN tools.
  - Nexus Dashboard.
  - Nautobot, the NetBox Platform MCP, the pamosima IOS-XE server, and the 1.13 entries.
- **Exit criterion 1 is not ticked:** the maintainer or orchestrator decides that.
- **No matrix row:** the task has none.

## Round 1 design findings on section 3 (moot after the maintainer decision)

1. `^(retrieve|list|find)` would make 12 typed config readers (cdot65 `retrieve_*`, mcfortigate `list_*` and `find_references`) `READ_OPERATIONAL`.
2. `^(list|get)_(… firewalls? …)` has no word boundary, so `get_firewall_policies` would be `INVENTORY_READ`. `get_clients_list` would hit `_list$`.
3. `pyats_rollback_config` would be `READ_CONFIG`.
4. Section 8 works only through profile notes, so with no profile `pyats_run_linux_command` and `execCommand` would be downgraded.

## Reproduce green

```sh
go test -count=1 -run 'FallbackBrief02|NotInBinary|NoProfileServerDeniesArguments' -v ./internal/classify/... ./internal/gate/ ./cmd/fathomgate/
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
```

## Decisions made without an ADR

- **Where the table lives:** it is a Go package, not JSON, so the rows keep `classify.Class` values and the `//nolint:misspell` lines. As a result, the classify test is an external test package (`classify_test`) to avoid an import cycle.

## Questions for the receiver

- None.
