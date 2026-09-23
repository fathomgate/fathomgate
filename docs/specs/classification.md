# Classification

Normative specification for how `internal/classify` assigns one class to every `tools/call`. The class comes from the upstream profile when the tool is mapped, and from the fallback classifier when it is not. Free-form commands are then inspected: an `EXEC_ARBITRARY` call is downgraded to `READ_OPERATIONAL` only when every command passes the allow-list, matches no blocklist and uses no forbidden pipe or redirect. Annotations can only make a class stricter.

Decision record: [ADR 0010](../adr/0010-classify-by-payload-not-annotations.md). Companion: [profile-schema.md](profile-schema.md).

## 1. Classes

| Class | Definition | Default policy |
| --- | --- | --- |
| `READ_OPERATIONAL` | Returns device or controller state and changes nothing persistent: facts, typed show tools, ping, traceroute, health checks, and free-form commands that passed section 5. | Allow, log, redact output. |
| `READ_CONFIG` | Returns running, startup or candidate configuration, diffs, backups, compliance results, or a dry-run of a change. Highest secret-leak risk. | Allow with mandatory redaction. |
| `WRITE_CONFIG` | Changes device or controller configuration, including staged loads, commits, confirms, aborts, rollbacks, and source-of-truth writes. | Deny by default; hold when policy allows; `dry_run` first where the tool has one. |
| `EXEC_ARBITRARY` | Executes a command the server does not filter with a positive allow-list, PFE or shell access, lab-node exec, XML `op` or XPath commands, dynamic scripts. | Deny; downgrade per section 5. |
| `INVENTORY_READ` | Lists devices, groups, tags, capabilities or pool state; source-of-truth reads. No device contact. | Allow; seeds the target list. |
| `LAB_LIFECYCLE` | Deploys or destroys labs, or starts and stops lab nodes. | Case by case; destroy is treated as a write. |
| `LOCAL_ADMIN` | Changes state on the proxy or server host, not the device: trust a host key, start a dashboard, subscribe telemetry, authenticate to a lab API. | Case by case. |

There is no eighth class. A new kind of operation is mapped to one of these; a new obligation is added to policy instead.

## 2. Order of operations

1. Look up `tool` in the profile. If found, take `class` and `class_source: profile`. If the tool has `capability_param` (a planned profile field, see [profile-schema.md](profile-schema.md#3-planned-fields-not-yet-parsed)), resolve through the capability table (`class_source: capability_table`).
2. If not found, run the fallback classifier (section 3), `class_source: fallback`, and set `profile_gap: true` on the audit event.
3. Apply annotations (section 4). They can only raise the class.
4. If the class is `EXEC_ARBITRARY` and `commands[]` is non-empty, run the downgrade rule (section 5).
5. If the class is `READ_OPERATIONAL` or was downgraded, run config-read redirection (section 6). A match sets `READ_CONFIG`.
6. If the class is `WRITE_CONFIG` and the request is a dry run (section 7), set `READ_CONFIG` and `dry_run_requested: true`.
7. Emit the class and the source to the request.

## 3. Fallback classifier

For a tool with no profile entry, in order, first match wins:

| Test | Class |
| --- | --- |
| Arguments contain any of `config_commands`, `config_lines`, `config_text`, `template_content`, `commands` paired with a name containing `config` or `set_` | `WRITE_CONFIG` |
| Tool name matches `^(create|update|delete|set|push|load|commit|apply|configure|rollback|abort|confirm|deploy|destroy)` | `WRITE_CONFIG` (`deploy`, `destroy` give `LAB_LIFECYCLE`) |
| Arguments contain `command` or `commands` | `EXEC_ARBITRARY` |
| Tool name matches `(exec|shell|pfe|op_command|xpath|run_linux|dynamic_test)` | `EXEC_ARBITRARY` |
| Tool name matches `(config|running|startup|backup|compliance|diff)` | `READ_CONFIG` |
| Tool name matches `^(list|get)_(devices?|routers?|targets?|firewalls?|groups?|tags?|device_types?)` or `_list$` | `INVENTORY_READ` |
| Tool name matches `(trust_host_key|start_dashboard|start_metrics|telemetry_(un)?subscribe|authenticate|health_check)` | `LOCAL_ADMIN` |
| Tool name matches `^(show|get|fetch|retrieve|list|search|find|ping|trace|test|gather|daily|collect)` | `READ_OPERATIONAL` |
| Anything else | `EXEC_ARBITRARY` |

The fallback exists so a new upstream works on day one with deny-by-default behaviour. The fix for a fallback classification is a profile entry, not a smarter fallback.

## 4. Annotations

| Annotation | Effect |
| --- | --- |
| `readOnlyHint: false` on a tool classed `READ_OPERATIONAL`, `READ_CONFIG` or `INVENTORY_READ` | Raise to `EXEC_ARBITRARY`; audit `class_source: annotation_raise` |
| `destructiveHint: true` on a tool classed `READ_*` | Same |
| `readOnlyHint: true` on anything | No effect |
| `destructiveHint: false` on anything | No effect |

Annotations are untrusted by the spec. They are used only in the direction that cannot be abused by a malicious server.

## 5. `EXEC_ARBITRARY` downgrade

Applied per command in `commands[]`. Every command MUST pass every check, or the class stays `EXEC_ARBITRARY`. A single failing command in a batch fails the whole call; the audit event names the first failing command and the check.

### 5.1 Normalise the command

- Trim; collapse internal whitespace to one space; lower-case for matching (the original is forwarded).
- Strip a trailing `| no-more` (Junos), `| no-page` (EOS) or `| begin`, `| include`, `| exclude`, `| section`, `| match`, `| count`, `| display set`, `| display xml`, `| display json`, `| json`, `| grep` filter chain for matching purposes, after checking section 5.4.

### 5.2 Allow-prefix list

The first word MUST be one of the vendor's allowed verbs. This is the union of netdev-ssh-mcp, mcp-telecom and pyATS.

| Vendor | Allowed first word |
| --- | --- |
| `ios`, `iosxe`, `nxos` | `show`, `ping`, `traceroute`, `dir`, `more` (only `more` of `flash:` or `bootflash:` paths not matching section 6), `terminal length`, `terminal width` |
| `eos` | `show`, `ping`, `traceroute`, `dir`, `terminal length` (`bash` is never allowed) |
| `junos` | `show`, `ping`, `traceroute`, `monitor` (only `monitor interface`, `monitor traffic` with `count`), `file list`, `test` |
| `iosxr` | `show`, `ping`, `traceroute`, `dir`, `terminal length` |
| `srlinux` | `show`, `info from state`, `ping`, `traceroute` (`tools` is never allowed) |
| `panos` | `show`, `test`, `ping`, `traceroute` |
| `fortios` | `get`, `diagnose sys top`, `diagnose ip arp list`, `diagnose ip route list`, `execute ping`, `execute traceroute` |
| `other` | `show`, `display`, `get`, `ping`, `traceroute` |

When the vendor is unknown, the `other` list applies.

### 5.3 Blocklist regexes

Even with an allowed prefix, a command matching any of these stays `EXEC_ARBITRARY`. Regexes are RE2, applied to the normalised lower-cased command.

| Id | Regex | Catches |
| --- | --- | --- |
| `bl-config-mode` | `^(configure|config\s+t|conf\s+t|edit|set\s|delete\s|no\s|commit|rollback|load\s|save\s|write\s|copy\s|erase|format|reload|request\s|restart|shutdown|clear\s|reset|debug|undebug|monitor\s+start|install|boot|zeroize|reboot|halt|power|activate|deactivate|license|crypto|archive\s+config|configure\s+replace|exec\b|start\s+shell|bash|python|guestshell|run\s)` | Config, file and system verbs at the start |
| `bl-embedded-verb` | `\b(reload|reboot|shutdown|write\s+erase|erase\s+startup|format\s+\w+:|zeroize|request\s+system|clear\s+(counters|logging|arp|ip|bgp|ospf|line))\b` | Dangerous words anywhere in the line |
| `bl-junos-op-side-effects` | `^(request|restart|clear|start|file\s+(copy|delete|rename)|test\s+configuration|load|commit|rollback)` | Junos operational verbs with side effects |
| `bl-eos-enable-shell` | `^(bash|enable|configure|reload|write|copy|delete|erase|boot|install|clear)` | EOS side effects |
| `bl-panos-side-effects` | `^(request|set|delete|commit|load|save|debug|clear|scp|tftp|ssh|ftp)` | PAN-OS side effects |
| `bl-fortios-side-effects` | `^(config|execute\s+(?!ping|traceroute)|diagnose\s+(debug|sys\s+(kill|session|flash)|hardware\s+deviceinfo\s+disk|npu))` | FortiOS write, restore, kill and debug |
| `bl-nxos-guestshell` | `^(guestshell|run\s+bash|python|dockerd|feature)` | NX-OS host access |
| `bl-tech-support-dump` | `show\s+tech(-support)?` | Not a write, but huge and secret-rich; policy MAY allow it through `READ_CONFIG` explicitly |

`show tech-support` is reclassified `READ_CONFIG` rather than left `EXEC_ARBITRARY`, since it contains the configuration.

### 5.4 Pipe and redirect ban

| Pattern | Effect |
| --- | --- |
| `>`, `>>`, `\|\s*(tee|save|redirect|append|copy)`, `\|\s*file` | Fail; redirects write |
| `;`, `&&`, `\|\|`, backtick, `$(` | Fail; shell chaining |
| `\|\s*(begin|include|exclude|section|match|count|grep|except|find|no-more|no-page|display\s+(set|xml|json)|json|trim|last|tab|resolve|compare|last)` | Allowed; output filters |
| Any other `\|` | Fail |

Junos `show configuration | compare rollback 1` is an output filter and passes here, but `show configuration` then hits section 6 and becomes `READ_CONFIG`, which is correct.

### 5.5 Result

If every command passes 5.2, 5.3 and 5.4, the class becomes `READ_OPERATIONAL` with `class_source: downgrade`. Section 6 then runs.

## 6. Config-read redirection

A free-form command that reads configuration is `READ_CONFIG`, so mandatory redaction applies and policies that allow `READ_OPERATIONAL` but not `READ_CONFIG` behave correctly. Applied to `READ_OPERATIONAL` calls with `commands[]`.

| Vendor | Regex |
| --- | --- |
| all | `^show\s+(run|running-config|start|startup-config|config|configuration|archive|derived-config|full-configuration|system\s+configuration)\b` |
| `junos` | `^show\s+configuration\b`, `^show\s+system\s+rollback\b`, `^file\s+show\s+/config/` |
| `eos` | `^show\s+(running-config|startup-config|session-config)\b`, `^more\s+flash:` |
| `nxos` | `^show\s+(running-config|startup-config|checkpoint)\b`, `^show\s+diff\s+rollback-patch\b` |
| `panos` | `^show\s+config\b`, `^show\s+(running|candidate)\b` |
| `fortios` | `^show\b`, `^get\s+system\s+(admin|interface|ha)\b`, `^diagnose\s+sys\s+ha\s+checksum\s+show\b` (FortiOS `show` is always config) |
| all | `show\s+tech` (see 5.3) |

The planned profile field `reads_config_when` will add patterns per upstream ([profile-schema.md](profile-schema.md#3-planned-fields-not-yet-parsed)).

## 7. Dry-run reclassification

Planned (M3; the profile fields are not parsed yet, see [profile-schema.md](profile-schema.md#3-planned-fields-not-yet-parsed)). A `WRITE_CONFIG` tool whose profile has `dry_run_param` or `apply_param` is `READ_CONFIG` for this call when:

- `dry_run_param` is present in the arguments and true, or absent and `dry_run_default` is true; and
- `apply_param`, if defined, is absent or false.

Examples: eos-mcp `push_config` with no `dry_run` argument (default true) is `READ_CONFIG`; junos `render_and_apply_j2_template` with `apply_config: false` is `READ_CONFIG`; ntunes `send_config` with `dry_run: true` is `READ_CONFIG`.

The audit event carries `dry_run_requested: true`. The proxy also uses these parameters to satisfy the `dry_run` obligation on a later real write.

## 8. Never downgraded

These stay `EXEC_ARBITRARY` regardless of command text, because the execution context is itself the risk:

- junos `execute_junos_pfe_command` (PFE shell)
- pyATS `pyats_run_linux_command`, `pyats_run_dynamic_test`
- clab `execCommand` (shell on a lab node)
- Palo-MCP `op` utility with raw XML, and XPath execution
- Any tool with `notes` containing `never-downgrade` in its profile

## 9. Worked examples

| Server, tool | Vendor | Arguments | Profile class | After downgrade | After redirect | Final | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| netdev `run_show_command` | eos | `show ip bgp summary` | READ_OPERATIONAL | n/a | no match | READ_OPERATIONAL | profile |
| netdev `run_show_command` | eos | `show running-config` | READ_OPERATIONAL | n/a | match | READ_CONFIG | reclassify |
| upa `send_command_and_get_output` | ios | `reload` | EXEC_ARBITRARY | `bl-config-mode` | | EXEC_ARBITRARY | profile |
| upa `send_command_and_get_output` | ios | `show ip route` | EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade |
| eos `run_command` | eos | `configure` | EXEC_ARBITRARY | `bl-eos-enable-shell` | | EXEC_ARBITRARY | profile |
| eos `run_command` | eos | `show version \| json` | EXEC_ARBITRARY | pass (filter pipe allowed) | no match | READ_OPERATIONAL | downgrade |
| eos `run_commands` | eos | `["show version", "reload now"]` | EXEC_ARBITRARY | second command fails | | EXEC_ARBITRARY | profile |
| ntunes `send_command` | nxos | `show running-config \| section bgp` | EXEC_ARBITRARY | pass | match | READ_CONFIG | reclassify |
| ntunes `send_command` | nxos | `show version > bootflash:v.txt` | EXEC_ARBITRARY | redirect ban | | EXEC_ARBITRARY | profile |
| junos `execute_junos_command` | junos | `show bgp summary \| no-more` | EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade |
| junos `execute_junos_command` | junos | `show configuration \| display set` | EXEC_ARBITRARY | pass | match | READ_CONFIG | reclassify |
| junos `execute_junos_command` | junos | `request system reboot` | EXEC_ARBITRARY | `bl-junos-op-side-effects` | | EXEC_ARBITRARY | profile |
| junos `execute_junos_pfe_command` | junos | `show jnh 0 exceptions` | EXEC_ARBITRARY | never downgraded | | EXEC_ARBITRARY | profile |
| junos `render_and_apply_j2_template` | junos | `apply_config: false` | WRITE_CONFIG | n/a | | READ_CONFIG | dry-run |
| junos `load_and_commit_config` | junos | any | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| eos `push_config` | eos | no `dry_run` given | WRITE_CONFIG | n/a | | READ_CONFIG | dry-run (default true) |
| eos `push_config` | eos | `dry_run: false` | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| mcfortigate `search_config` | fortios | `term: admin` | READ_CONFIG | n/a | | READ_CONFIG | profile |
| netdev `run_show_command` | fortios | `get system status` | READ_OPERATIONAL | n/a | no match | READ_OPERATIONAL | profile |
| ntunes `send_command` | fortios | `show system interface` | EXEC_ARBITRARY | fail: `show` is not on the fortios allow-list | | EXEC_ARBITRARY | profile |
| ntunes `send_command` | panos | `show system info` | EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade |
| ntunes `send_command` | panos | `show config running` | EXEC_ARBITRARY | pass | match | READ_CONFIG | reclassify |
| meraki `execute_api` | other | `capability_id: getNetworkDevices` | via table | `^get` → READ_OPERATIONAL | | READ_OPERATIONAL | capability_table |
| meraki `execute_api` | other | `capability_id: rebootDevice` | via table | `^reboot` → WRITE_CONFIG | | WRITE_CONFIG | capability_table |
| clab `destroyLab` | n/a | any | LAB_LIFECYCLE | | | LAB_LIFECYCLE | profile |
| unknown server, tool `frobnicate` | n/a | `{command: "show clock"}` | fallback → EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade, `profile_gap` |

The FortiOS `show system interface` row is deliberate: on FortiOS `show` prints configuration, so it is not on the allow-list and the tool stays `EXEC_ARBITRARY`; the correct path is `get system interface` or a typed config tool, which is `READ_CONFIG`.

## 10. Test expectations

Tier 1 table tests in `internal/classify` cover every row in section 9. Each vendor allow-list and blocklist entry has at least one positive and one negative case. The Python `tools/policy-lint` reuses the same regex tables, exported as `classify/rules.yaml`, so the two implementations cannot drift.
