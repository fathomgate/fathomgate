# Profile schema

Normative specification for the per-upstream-server profile. A profile tells `internal/classify` which class each tool has and where the target, command and configuration payload live in each tool's arguments. One YAML file per upstream server lives in `profiles/`. Profiles are data; adding one needs no Go.

This document describes what `internal/classify/profile.go` and `normalize.go` parse. The loader is strict: a key not listed in sections 1 or 2 is a load error. Fields the plan calls for but the loader does not yet accept are listed in section 3 and MUST NOT appear in a profile today. Decision record: [ADR 0010](../adr/0010-classify-by-payload-not-annotations.md). Companion: [classification.md](classification.md), [inventory-schema.md](inventory-schema.md).

## 1. Top-level fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `server` | string, non-empty | yes | Short name used as the tool prefix toward the agent (`netdev-ssh-mcp.get_config`) and in policy `match.servers`. MUST be unique across the `profiles/` directory; `LoadProfileDir` rejects duplicates. |
| `source` | string (URL) | no | Repository the profile was written against. |
| `description` | string | no | One line for humans. |
| `tools` | map of tool name to tool spec | yes, non-empty | Every tool the upstream exposes. A tool absent from the profile normalises to nothing and is treated as `EXEC_ARBITRARY`. |

Comments at the top of the file record the research brief section the tool names came from and the upstream's own safety features. That is convention, not schema.

## 2. Tool spec

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `class` | class | yes | Class assigned before any argument inspection. One of `READ_OPERATIONAL`, `READ_CONFIG`, `WRITE_CONFIG`, `EXEC_ARBITRARY`, `INVENTORY_READ`, `LAB_LIFECYCLE`, `LOCAL_ADMIN`. The loader accepts lower case and `-` for `_`. |
| `target_params` | list of string | no | Argument names holding a single target (`host`, `hostname`, `name`, `device`, `router_name`, `target`, `firewall`). |
| `targets_params` | list of string | no | Argument names holding a list of targets, as an array or a comma-separated string (`devices`, `hostnames`, `router_names`). |
| `group_params` | list of string | no | Argument names holding group or tag selectors (`tags`). Each value is emitted as an `@name` token for the inventory to expand. |
| `command_params` | list of string | no | Argument names holding operational commands, as a string or an array (`command`, `commands`). |
| `config_params` | list of string | no | Argument names holding configuration payload (`config_commands`, `config_lines`, `config_text`, `template_content`). |
| `notes` | string | no | Free text for humans: server-side safety, caveats, the source line. |

### 2.1 Normalisation rules

Implemented in `Normalize(profile, tool, args)`:

- Targets are gathered in order from `target_params`, then `targets_params`, then `group_params`. Values are trimmed and de-duplicated. A `targets_params` value that is a string is split on commas.
- A `group_params` value gets an `@` prefix unless it already has one. An `@group` token already present in any target argument passes through unchanged. The inventory expands `@` tokens later ([inventory-schema.md](inventory-schema.md#8-expansion-before-resolution)).
- `commands[]` is built from `command_params`: a string becomes one element; an array becomes many. Empty strings are dropped.
- `config_payload` is every `config_params` value joined with newlines, in the order listed.
- A tool is looked up by its bare name or by `<server>.<name>`.
- A tool not in the profile yields empty targets, commands and payload; callers treat it as `EXEC_ARBITRARY`.

A tool with a `command_params` or `config_params` but no target source (eos-mcp `run_command_batch` with only `hostnames` and `tags` selectors, both optional upstream) can arrive with zero targets. What zero targets means for policy is decided by the policy's `device_roles` and `device_tags` matchers, which do not match a request with no targets.

## 3. Planned fields (not yet parsed)

These are in the plan and in the research but the strict loader rejects them today. Put the information in `notes` until the field lands.

| Field | Intended meaning | Milestone |
| --- | --- | --- |
| `dry_run_param`, `dry_run_default`, `apply_param` | Which argument makes the tool a dry run or a real apply, so the classifier can reclassify a dry run as `READ_CONFIG` and the `dry_run` obligation can be satisfied through the tool itself (eos-mcp `push_config`, ntunes `send_config`, junos `render_and_apply_j2_template`). | M3 |
| `config_format_param` | Argument naming the payload format (`set`, `text`, `xml`). | M3 |
| `fanout_params` | `max_concurrent`, `max_workers`; the proxy would cap them. | M4 |
| `targets_all_when_empty` | Empty selection means every device in the upstream inventory (eos-mcp batch tools). | M2 |
| `implicit_target` | One device or controller per process (PAN-OS, FortiOS single mode); the target is the server name. | M5 |
| `reads_config_when` | Extra config-read regexes per upstream. | M2 |
| `capability_param`, `capability_table`, top-level `capabilities` | Meta-tool classification from a parameter (Meraki `execute_api(capability_id)`). | M1 (planned) |
| `inventory_tool`, `inventory_map` | Which `INVENTORY_READ` tool seeds the resolver chain's upstream provider. | M2 |
| `transport`, `era`, `vendor_hint`, `verified_version` | Launch and era configuration; today these live in `netguard serve` flags. | M2 |

## 4. Example: netdev-ssh-mcp

`profiles/netdev-ssh-mcp.yaml` as it exists on disk. Tool names and parameters are from [research brief 02, section 1.1](../research/02-network-mcp-servers.md), read from `main.go`.

```yaml
server: netdev-ssh-mcp
source: https://github.com/krisiasty/netdev-ssh-mcp
description: Read-only multi-vendor SSH server (EOS, IOS/IOS-XE, NX-OS, Junos, FortiOS)
tools:
  get_config:
    class: READ_CONFIG
    target_params: [host]
    notes: config_type running|startup; output is obfuscated server-side, redacted again by the proxy.
  run_show_command:
    class: READ_OPERATIONAL
    target_params: [host]
    command_params: [command]
    notes: Server enforces a show/get prefix; the proxy re-checks and escalates config dumps to READ_CONFIG.
  run_ping:
    class: READ_OPERATIONAL
    target_params: [host]
    notes: destination, count, timeout, source, vrf, size, outgoing_interface are typed args, not commands.
  run_traceroute:
    class: READ_OPERATIONAL
    target_params: [host]
  trust_host_key:
    class: LOCAL_ADMIN
    target_params: [host]
    notes: Writes known_hosts on the MCP server host, not on the device. Two-step confirm flow.
```

Because `host` is free-form and the server has no inventory, every target goes through the resolver chain. A host absent from every provider is unknown.

## 5. Example: junos-mcp-server

`profiles/junos-mcp-server.yaml` as it exists on disk. Tool names and `inputSchema` are from [research brief 02, section 1.7](../research/02-network-mcp-servers.md), read from `jmcp.py` `list_tools()`.

```yaml
server: junos-mcp-server
source: https://github.com/Juniper/junos-mcp-server
description: Official Juniper Junos server over PyEZ
tools:
  execute_junos_command:
    class: EXEC_ARBITRARY
    target_params: [router_name]
    command_params: [command]
    notes: Server applies block.cmd regexes; proxy downgrades to READ_OPERATIONAL/READ_CONFIG when the command passes the allow-list.
  execute_junos_pfe_command:
    class: EXEC_ARBITRARY
    target_params: [router_name]
    command_params: [command]
    notes: PFE shell on an FPC (`target`). Never downgraded in practice because PFE commands do not start with show.
  execute_junos_command_batch:
    class: EXEC_ARBITRARY
    targets_params: [router_names]
    command_params: [command]
    notes: Fleet-wide; targets_count rules apply.
  get_junos_config:
    class: READ_CONFIG
    target_params: [router_name]
  junos_config_diff:
    class: READ_CONFIG
    target_params: [router_name]
    notes: version 1-49 selects the rollback to diff against.
  gather_device_facts:
    class: READ_OPERATIONAL
    target_params: [router_name]
  get_router_list:
    class: INVENTORY_READ
    notes: Seeds the proxy's target allow-list at startup (M1).
  load_and_commit_config:
    class: WRITE_CONFIG
    target_params: [router_name]
    config_params: [config_text]
    notes: Immediate commit; config_format set|text|xml. Server applies block.cfg line-by-line. M3 adds commit-check + commit confirmed.
  render_and_apply_j2_template:
    class: WRITE_CONFIG
    target_params: [router_name]
    targets_params: [router_names]
    config_params: [template_content, vars_content]
    notes: Render-only unless apply_config=true; dry_run=true is commit-check + rollback. Classified WRITE_CONFIG conservatively; M1 may relax when apply_config is false.
```

`render_and_apply_j2_template` is `WRITE_CONFIG` even when `apply_config` is false, because the loader has no `apply_param` yet (section 3). The conservative class is correct: a policy that allows reads but not writes denies the render, and the operator can add a `tools: [render_and_apply_j2_template]` allow rule if rendering without applying is wanted.

## 6. Other shipped profiles

The rows show the normalisation keys that differ. Full files are in `profiles/`.

| Server | Tool | class | target_params | targets_params | group_params | command_params | config_params |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ntunes-netmiko-mcp-server` | `send_command` | `EXEC_ARBITRARY` | `[device]` | | | `[command]` | |
| `ntunes-netmiko-mcp-server` | `send_command_parallel` | `EXEC_ARBITRARY` | | `[devices]` (may carry `@group` tokens) | | `[command]` | |
| `ntunes-netmiko-mcp-server` | `send_commands_sequence` | `EXEC_ARBITRARY` | `[device]` | | | `[commands]` | |
| `ntunes-netmiko-mcp-server` | `send_config` | `WRITE_CONFIG` | `[device]` | | | | `[config_commands]` |
| `ntunes-netmiko-mcp-server` | `send_config_parallel` | `WRITE_CONFIG` | | `[devices]` | | | `[config_commands]` |
| `ntunes-netmiko-mcp-server` | `list_devices`, `list_groups`, `get_device_types`, `get_tags`, `get_pool_status` | `INVENTORY_READ` | | | | | |
| `ntunes-netmiko-mcp-server` | `get_device_info` | `INVENTORY_READ` | `[device]` | | | | |
| `ntunes-netmiko-mcp-server` | `test_connection` | `READ_OPERATIONAL` | `[device]` | | | | |
| `eos-mcp` | `run_command` | `EXEC_ARBITRARY` | `[hostname]` | | | `[command]` | |
| `eos-mcp` | `run_commands` | `EXEC_ARBITRARY` | `[hostname]` | | | `[commands]` | |
| `eos-mcp` | `run_command_batch` | `EXEC_ARBITRARY` | | `[hostnames]` | `[tags]` | `[command]` | |
| `eos-mcp` | `run_commands_batch` | `EXEC_ARBITRARY` | | `[hostnames]` | `[tags]` | `[commands]` | |
| `eos-mcp` | `get_router_list` | `INVENTORY_READ` | | | `[tags]` | | |
| `eos-mcp` | `get_device_facts`, `get_version`, `collect_tech_support` | `READ_OPERATIONAL` | `[hostname]` | | | | |
| `eos-mcp` | `get_device_facts_batch`, `daily_brief` | `READ_OPERATIONAL` | | `[hostnames]` | `[tags]` | | |
| `eos-mcp` | `get_config`, `get_config_diff`, `list_config_sessions` | `READ_CONFIG` | `[hostname]` | | | | |
| `eos-mcp` | `push_config` | `WRITE_CONFIG` | `[hostname]` | | | | `[config_lines]` |
| `eos-mcp` | `confirm_config_session`, `abort_config_session` | `WRITE_CONFIG` | `[hostname]` | | | | |
| `eos-mcp` | `health_check` | `LOCAL_ADMIN` | | | | | |

Profiles for upa/mcp-netmiko-server, Palo-MCP, mcfortigate and the Meraki meta-tool are planned; the Meraki one waits on the capability-table fields in section 3.

## 7. Validation

`ParseProfile` and `LoadProfileDir` check:

- strict YAML: no unknown keys at either level;
- `server` is non-empty;
- `tools` is non-empty;
- every tool's `class` is a known class;
- `server` is unique across the directory.

`internal/classify/profiles_repo_test.go` loads every file in `profiles/` in tier 1. A tier 2 test that compares each profile against the real upstream's `tools/list` is planned ([test-strategy.md](../testing/test-strategy.md)).
