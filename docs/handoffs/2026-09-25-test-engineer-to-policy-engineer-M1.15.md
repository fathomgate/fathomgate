# Fallback-classification table test for every other surveyed tool, with design findings on the planned fallback classifier

- **Task:** M1-15 — Tier 1 fallback-classification tests for every other surveyed tool in brief 02
- **From → To:** test-engineer → policy-engineer
- **State now:** in review
- **Branch / PR:** test/m1-15-fallback-classes · https://github.com/fathomgate/fathomgate/pull/193
- **Date:** 2026-09-25

## Done

- `internal/classify/fallback_brief02_test.go` (new, test only):
  - `TestFallbackBrief02` has one row per tool that brief 02 names on a server with no shipped profile: 138 tools on 14 servers. That is mcp-telecom 55, mcfortigate 17, pyATS 15, netbox-mcp-rw 9, network-discovery 8, Catalyst Center 7, clab 6, NetBox 4, Palo-MCP 4, cdot65 pan-os 4, fortigate-mcp 4, SD-WAN 3, scrapli 1 and Meraki `semantic_search` 1.
  - Each row runs three ways: `Classify(nil, …)`, the empty profile that `serve` gives such a server (bare tool name), and the same profile with the `server.tool` name.
  - Each run asserts:
    - `class_source: fallback`, and the tool is unknown.
    - The class is at least as strict as brief 02's class. The yardstick is `brief02Strictness`, ordered by how the three example policies treat each class.
    - `EXEC_ARBITRARY` where the brief gives no class, and for the section 8 tools (`pyats_run_linux_command`, `pyats_run_dynamic_test`, clab `execCommand`, each sent a command the allow-list would pass).
    - Under the empty profile, every argument is in `UnnamedArgs`, so the gate denies the call with `default:bad_arguments`.
  - `TestFallbackBrief02Table` guards the table. No server key may have a shipped profile (when one lands, its rows move to `TestRepoProfiles`). Rows must not repeat. There is no Meraki `execute_api` row. `brief02Known` (currently empty) must have no stale entries.
- The row for the brief's class comes from section 2(c), then Part 1. Where the two disagree, the row takes the stricter class.
- Some names and arguments are representative, and the rows say so: one name per fortigate-mcp family (`get_*`, `create_*`, `update_*`, `delete_*`), Palo-MCP arguments, and network-discovery arguments.
- Docs: `docs/specs/classification.md` section 10 gets a pointer to the test, and there is a CHANGELOG `Unreleased` entry.

## Findings (yours, policy-engineer)

Against the code: **none.** The fallback is `EXEC_ARBITRARY` for every tool, so no row is less strict than brief 02, and `brief02Known` is empty. Nothing is skipped.

Against the planned section 3 classifier, which is not implemented yet: I simulated its table over the same rows. If it lands as written, this test fails on these rows, and that failure is intended:

1. **Typed config readers become `READ_OPERATIONAL` (brief says `READ_CONFIG`).** `^(retrieve|list|find)` matches before any config test does:
   - cdot65 `retrieve_address_objects`, `retrieve_security_zones` and `retrieve_security_policies`.
   - mcfortigate `list_address_objects`, `list_address_groups`, `list_services`, `list_policies`, `list_vips`, `find_references`, `list_interfaces`, `list_vlans` and `list_static_routes`.

   That is 12 tools that would lose mandatory redaction.
2. **`^(list|get)_(… firewalls? …)` has no word boundary.** fortigate-mcp `get_firewall_policies` would be `INVENTORY_READ` (brief says `READ_CONFIG`). Catalyst Center `get_clients_list` would hit `_list$` and be `INVENTORY_READ` (brief says `READ_OPERATIONAL`).
3. **pyATS `pyats_rollback_config(device)` would be `READ_CONFIG`** (brief says `WRITE_CONFIG`). The name has no `^rollback` prefix, and the arguments carry no `commands`, so the `config` substring test catches it.
4. **Section 8 has no effect without a profile.** `pyats_run_linux_command` and clab `execCommand` carry `command`. Section 3 makes them `EXEC_ARBITRARY`, and step 4 then downgrades them: `ping 192.0.2.1` would pass on a Linux host. Section 8 is enforced only through the profile's `never-downgrade` notes. Either the fallback must never downgrade (as the code does today), or section 3 needs its own never-downgrade name list. The worked example `frobnicate` expects a downgrade, which conflicts with this.
5. **Minor:** tools the brief does not classify would get a read class instead of `EXEC_ARBITRARY`: SD-WAN `list_devices`, `get_control_connections` and `get_bfd_summary`, Catalyst Center `get_api_compatible_time_range`, and network-discovery `collect_device_configs`. `collect_device_configs` contacts live devices.

## Look at this first

- `brief02Strictness` and the `switch` in `TestFallbackBrief02`. Check whether you agree with the order (`LOCAL_ADMIN` and `LAB_LIFECYCLE` stricter than `READ_CONFIG`).

## Deliberately unfinished

- **Surfaces the brief names without tool names, which cannot be tested:**
  - CloudVision.
  - clab FloSch62.
  - The other 113 Palo-MCP tools (including the `op` and XPath tools).
  - The other 389 fortigate-mcp tools.
  - The other 36 SD-WAN tools.
  - Nexus Dashboard's 638 operations.
  - Nautobot, the NetBox Platform MCP, the pamosima IOS-XE server, and the 1.13 entries.

  Brief 02 or upstream-server-scout would have to name these tools first.
- **Exit criterion 1 is not ticked:** the maintainer or orchestrator decides that.
- **No matrix row:** the task has none.

## Reproduce green

```sh
go test -count=1 -run 'TestFallbackBrief02' -v ./internal/classify
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
```

## Decisions made without an ADR

- **Unclassed tools:** a tool the brief names but does not class must be `EXEC_ARBITRARY`, which is deny by default.
- **Strictness order:** `brief02Strictness` is a test yardstick, not an interface.

## Questions for the receiver

- Should findings 1 to 4 go into classification.md section 3 now, before anyone implements it, or wait for the task that implements it?
