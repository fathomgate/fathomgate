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

`classify.Result.ClassSource` carries the source, spelled as in the audit event's `class_source`:

| Source | Set when | Emitted today |
| --- | --- | --- |
| `profile` | The profile's class stands: no commands, commands that confirm it, a failed downgrade, or a `never-downgrade` tool. | yes |
| `fallback` | No profile, or the tool is not in it. | yes |
| `downgrade` | An `EXEC_ARBITRARY` call whose every command passed section 5 is `READ_OPERATIONAL`. | yes |
| `reclassify` | The commands moved the class anywhere else: an `EXEC_ARBITRARY` or `READ_OPERATIONAL` call whose commands read configuration is `READ_CONFIG` (section 6), and a `READ_OPERATIONAL` call whose command fails section 5 is `EXEC_ARBITRARY` (defence in depth against a server whose own filter is weaker than its tool name). | yes |
| `capability_table` | Step 1 through a capability table. | no, M1-17 |
| `annotation_raise` | Step 3 raised the class. | no, M1-18 (ADR 0026, proposed) |

What the code does not do yet: step 2 has no fallback classifier (section 3), so a tool missing from the profile is `EXEC_ARBITRARY` and is never downgraded; step 3 has no annotation input; step 6 is M3 (section 7). Those three are stricter than the design.

The code is looser than the design in one place: it does not know the vendor, so a FortiOS `show` whose second word is not a config keyword (`show vpn ipsec phase1-interface`, `show user local`, both carrying `ENC` secrets) is `READ_OPERATIONAL` where the design's FortiOS allow-list makes it `EXEC_ARBITRARY`. The same holds on every vendor for operational commands that print secrets (IOS and NX-OS `show snmp community`, `show key chain`, `show crypto isakmp key`). This is accepted and open until the vendor reaches `Classify`, which needs a decision record. Until then the mitigation depends on M2: redaction MUST run on every tool result, whatever the class and whether or not a rule carries the `redact` obligation (invariant 4), not only on `READ_CONFIG` calls.

`Result.Reason` never contains agent-supplied text: a failed command is named by its 1-based index and the check (`command 2 failed the read allow-list (blocklist)`), and an unknown tool is "tool not in profile" (the tool name is in the structured request). The `never-downgrade` token (section 8) is matched case-insensitively.

## 3. Fallback classifier

Planned; not implemented. Today a tool with no profile entry is `EXEC_ARBITRARY` with `class_source: fallback`, whatever its arguments, and is not downgraded.

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

Not implemented yet: `Classify` has no annotation input. The input arrives with M1-18 through `internal/gate` (ADR 0026, proposed), and can only raise.

## 5. `EXEC_ARBITRARY` downgrade

Applied per command in `commands[]`. Every command MUST pass every check, or the class stays `EXEC_ARBITRARY`. A single failing command in a batch fails the whole call; `Result.Reason` (and, from M1-18, the audit event) names the first failing command by its index, never its text, and the check.

The checks are vendor-agnostic. The device vendor is not known when a call is classified (roles and vendors are resolved afterwards, per target, and one call can fan out to several vendors), so the code applies one list: the union of the strongest filters the surveyed servers ship, conservative enough to be right on every vendor. The per-vendor tables in sections 5.6 and 6.1 are the design for when the vendor reaches `Classify`, which is an interface change and needs a decision record.

Checks run in this order; the first failure names the check.

| Check id | Fails when |
| --- | --- |
| `too-long` | The command is longer than 1024 bytes. No read needs more. |
| `control-character` | The command, after trimming leading and trailing spaces and tabs, contains any byte below `0x20` other than tab, or `0x7f`: newline, carriage return, vertical tab, form feed, NUL, Ctrl-C, Ctrl-Z, escape. A second line would otherwise vanish into a space while the device still runs it. |
| `non-ascii` | Any byte is `0x80` or above: no-break space, line separator, zero-width space, fullwidth look-alikes. |
| `empty` | Nothing is left after trimming; also an empty `commands[]`, and an empty or whitespace-only element of it. |
| `shell-meta` | The command contains `\|`, `<`, `>`, `;`, `&`, a backtick, `"`, `'`, a backslash, `{`, `}`, `*`, `?`, `[`, `]`, `~`, or a `$` followed by anything but a space or the end of the line (section 5.4). |
| `leading-dash` | Any word after the first starts with `-`: an option to whatever parses the line (`ping -f`, `traceroute --help`). Network CLIs take none on read commands; on a server that runs ping or traceroute on its own host it is option injection. |
| `blocklist` | Section 5.3 matches. |
| `monitor-no-count` | Junos `monitor traffic` without a `count <n>` pair with `n` from 1 to 1000; without it the capture runs until interrupted (section 5.6). |
| `allow-prefix` | Section 5.2 does not match. |

A command that passes every check and reads configuration (section 6) is `READ_CONFIG`; otherwise it is `READ_OPERATIONAL`.

### 5.1 Normalise the command

- Check the raw command for `control-character` and `non-ascii` first, so whitespace collapsing cannot hide a line break. netmiko sends an embedded line break to the device, which runs each line, and other drivers are not assumed to be safer; the security review of PR #150 showed `show clock\nconf t\nhostname pwned\nend` allowed as `READ_OPERATIONAL` before this check.
- Space and tab are the only whitespace. A tab is horizontal whitespace: on an interactive CLI it at most completes the current word, and over eAPI or NETCONF it is a separator, so it cannot start a second command. Tabs are collapsed like spaces, which is why `show<TAB>running-config` is `READ_CONFIG`. Newline, carriage return, vertical tab, form feed, the C0 and C1 controls, NEL (U+0085) and the Unicode line and paragraph separators (U+2028, U+2029) are not whitespace; they fail.
- Normalisation trims each command of spaces and tabs only, so a line break at either end (`show version` followed by a newline) is kept and fails, and it keeps empty and whitespace-only elements of `commands[]`, which fail `empty` instead of vanishing from the batch.
- Collapse internal spaces and tabs to one space; lower-case for matching. The original is forwarded unchanged (apart from trimming), so `show  running-config` and `show<TAB>running-config` match as `show running-config`.
- No output filter is stripped: every pipe fails in section 5.4.

### 5.2 Allow-prefix list

The first word MUST be one of these (RE2, on the normalised command):

```
^(?:show|get|display|monitor\s+traffic|ping|traceroute|tracepath)(?:\s|$)
```

`monitor` is allowed only as Junos `monitor traffic`, and only with `count <n>` where `n` is 1 to 1000 (check `monitor-no-count`). Junos `monitor interface` takes no count and runs until interrupted, so it is not on the list; IOS-XE `monitor capture` defines capture points and exports files, and Junos `monitor start` is not a read. `terminal length`, `dir`, `more`, `file list`, `test`, `enable`, `bash` and every abbreviation (`sh run`) fail.

### 5.3 Blocklist

Even with an allowed prefix, a command matching either regex stays `EXEC_ARBITRARY` (check `blocklist`).

The start-anchored list is `bl-config-mode` and the vendor rows of section 5.6 as one list. None of its verbs is on the allow-prefix list, so today those commands fail section 5.2 as well; the list keeps them failing if section 5.2 ever grows:

```
^(?:configure|config|conf|edit|set|delete|no|commit|rollback|load|save|write|wr|copy|erase|format|reload|rel|relo|request|restart|shutdown|clear|reset|debug|undebug|monitor\s+start|install|boot|zeroize|reboot|halt|power|activate|deactivate|license|crypto|archive|exec|start|bash|python|guestshell|tclsh|run|enable|feature|dockerd|scp|tftp|ssh|ftp|telnet|execute|diagnose|file|test)(?:\s|$)
```

The anywhere list matches a verb in any position, bounded by whitespace or the ends of the line, so `show system reset-reason` and `show interfaces no-shutdown` pass while `show reload` fails. It carries the abbreviations device CLIs accept (`conf t`, `wr`, `rel`, `relo`) so that the payload of a multi-line injection fails here too, even flattened onto one line. Words that are also common show arguments (`boot`, `install`, `enable`, `no`) are only in the start-anchored list, so `show boot` and `show install summary` stay reads:

```
(?:^|\s)(?:configure|conf(?:i(?:g(?:u(?:re?)?)?)?)?\s+t(?:e(?:r(?:m(?:i(?:n(?:al?)?)?)?)?)?)?|edit|set|delete|rollback|commit|wr(?:i(?:te?)?)?|write-file|copy|rel(?:o(?:ad?)?)?|reboot|shutdown|clear|reset|format|erase|debug|undebug|request\s+system|zeroize|admin\s+(?:save|reboot)|tclsh|bash|python|guestshell|start\s+shell)(?:\s|$)
```

`write-file` is the Junos `monitor traffic` option that writes a capture to disk.

The lists fail closed, and some reads fail with them. Known and accepted (security review of PR #152): `show debug`, Junos `show system commit`, `show system rollback` spelled in full, `show configuration commit list` and any show argument that is a blocklisted word stay `EXEC_ARBITRARY`.

### 5.4 Pipe and redirect ban

Every `|`, `<`, `>`, `;`, `&` and backtick fails, including the output filters section 5.6 would allow (`| json`, `| no-more`, `| section bgp`, `| display set`). This is stricter than the design; an agent that needs a filter uses a typed tool or asks for the unfiltered command.

`"`, `'`, backslash, `{`, `}`, `*`, `?`, `[`, `]`, `~` and `$` fail too. On a server whose command reaches a shell on its own host, they rebuild what the leading-dash check looks for: `ping 1.1.1.1 "-f"`, `'-f'` and a backslash-escaped `-f` become `-f`, `ping {-f,1.1.1.1}` is brace-expanded, `[-]f`, `*` and `?` are globbed, `~root` is a home directory, and `$'...'`, `$HOME`, `$(...)` and `${IFS}` are rewritten. A `$` at the end of a word (followed by a space or the end of the line) is allowed: no shell expands it, and it is the regex anchor in IOS `show ip bgp regexp _65000$`.

### 5.5 Result

If every command passes, the class becomes `READ_OPERATIONAL` with `class_source: downgrade`. Section 6 then runs; a match makes the call `READ_CONFIG` with `class_source: reclassify`. A tool whose profile notes carry `never-downgrade`, in any case, skips the downgrade (section 8).

### 5.6 Planned: per-vendor tables

Not implemented; they need the vendor at classification time (see above).

The first word MUST be one of the vendor's allowed verbs. This is the union of netdev-ssh-mcp, mcp-telecom and pyATS.

| Vendor | Allowed first word |
| --- | --- |
| `ios`, `iosxe`, `nxos` | `show`, `ping`, `traceroute`, `dir`, `more` (only `more` of `flash:` or `bootflash:` paths not matching section 6), `terminal length`, `terminal width` |
| `eos` | `show`, `ping`, `traceroute`, `dir`, `terminal length` (`bash` is never allowed) |
| `junos` | `show`, `ping`, `traceroute`, `monitor` (only `monitor interface`, `monitor traffic` with `count`; the code allows only `monitor traffic` with `count` 1 to 1000), `file list`, `test` |
| `iosxr` | `show`, `ping`, `traceroute`, `dir`, `terminal length` |
| `srlinux` | `show`, `info from state`, `ping`, `traceroute` (`tools` is never allowed) |
| `panos` | `show`, `test`, `ping`, `traceroute` |
| `fortios` | `get`, `diagnose sys top`, `diagnose ip arp list`, `diagnose ip route list`, `execute ping`, `execute traceroute` |
| `other` | `show`, `display`, `get`, `ping`, `traceroute` |

When the vendor is unknown, the `other` list applies.

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

The planned pipe rules, instead of the blanket ban of section 5.4:

| Pattern | Effect |
| --- | --- |
| `>`, `>>`, `\|\s*(tee|save|redirect|append|copy)`, `\|\s*file` | Fail; redirects write |
| `;`, `&&`, `\|\|`, backtick, `$(` | Fail; shell chaining |
| `\|\s*(begin|include|exclude|section|match|count|grep|except|find|no-more|no-page|display\s+(set|xml|json)|json|trim|last|tab|resolve|compare|last)` | Allowed; output filters |
| Any other `\|` | Fail |

Junos `show configuration | compare rollback 1` is an output filter and passes here, but `show configuration` then hits section 6 and becomes `READ_CONFIG`, which is correct.

## 6. Config-read redirection

A free-form command that reads configuration is `READ_CONFIG`, so mandatory redaction applies and policies that allow `READ_OPERATIONAL` but not `READ_CONFIG` behave correctly. Applied to `READ_OPERATIONAL` calls with `commands[]` and to downgraded calls; `class_source: reclassify`. It runs after the blocklist, so `show configure` stays `EXEC_ARBITRARY`.

Implemented vendor-agnostically on the normalised words (`isConfigRead` in `internal/classify/command.go`). Vendor CLIs accept any unambiguous abbreviation (`show ru`, `show tec`, Junos `show sys rol 1`), so keywords are matched by prefix in both directions: a word matches a keyword when it is a prefix of the keyword or the keyword is a prefix of it. Matching too much only makes a read `READ_CONFIG`, the stricter read class. A command with first word `show`, `display` or `get` is `READ_CONFIG` when:

1. it has no second word: a bare FortiOS `show` prints the whole configuration; or
2. its second word matches one of `running-config`, `startup-config`, `configuration`, `config`, `tech-support`, `derived-config`, `archive`, `full-configuration`, `current-configuration`, `saved-configuration`, `session-config`, `checkpoint`, `candidate`, `file`, `diff`; or
3. its second word is a prefix of `system` (`sys`, `system`) and its third word matches one of `rollback`, `configuration`, `admin`, `interface`, `ha`.

This covers the "all" rows below, `show tech-support`, Junos `show system rollback` in short form (`show sys rol 1`, the previous configuration with its `$9$` secrets; spelled in full, `rollback` hits the blocklist and the call stays `EXEC_ARBITRARY`), EOS `session-config` and `config-sessions`, NX-OS `checkpoint`, `show file bootflash:backup.cfg` (saved configs live on bootflash) and `show diff rollback-patch checkpoint cp1 running-config` (config diff lines with password hashes; `rollback-patch` is one hyphenated word, so the blocklist does not catch it), PAN-OS `show config running` and `candidate`, Huawei `display current-configuration` and `saved-configuration`, and FortiOS `get system admin|interface|ha` (and `show system interface`, whichever vendor). Short second words over-match on purpose: `show c`, `show a`, `show s`, `show d`, `show f` and `show file systems` are `READ_CONFIG`, and after `system` the `ha` keyword makes `get system hardware` `READ_CONFIG`. Not covered, and stricter as a result: `file show /config/` and `more flash:` fail the allow-prefix list and stay `EXEC_ARBITRARY`. FortiOS `show` with another second word is not `READ_CONFIG` until the vendor reaches `Classify` (section 2).

### 6.1 Planned: per-vendor patterns

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

The mechanism is the last item: `Classify` skips the downgrade for an `EXEC_ARBITRARY` tool whose profile notes contain `never-downgrade` (matched case-insensitively, so `Never-Downgrade` counts), and the class source stays `profile`. Of the tools above, only junos `execute_junos_pfe_command` has a shipped profile, and it carries the token; the others MUST carry it when their profiles land.

## 9. Worked examples

What the code does today. Rows marked † differ from the vendor-aware design; the note under the table gives the design's answer. All are stricter than the design except the FortiOS row.

| Server, tool | Vendor | Arguments | Profile class | After downgrade | After redirect | Final | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| netdev `run_show_command` | eos | `show ip bgp summary` | READ_OPERATIONAL | n/a | no match | READ_OPERATIONAL | profile |
| netdev `run_show_command` | eos | `show running-config` | READ_OPERATIONAL | n/a | match | READ_CONFIG | reclassify |
| upa `send_command_and_get_output` | ios | `reload` | EXEC_ARBITRARY | fail: `blocklist` | | EXEC_ARBITRARY | profile |
| upa `send_command_and_get_output` | ios | `show ip route` | EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade |
| eos `run_command` | eos | `configure` | EXEC_ARBITRARY | fail: `blocklist` | | EXEC_ARBITRARY | profile |
| eos `run_command` † | eos | `show version \| json` | EXEC_ARBITRARY | fail: `shell-meta` | | EXEC_ARBITRARY | profile |
| eos `run_commands` | eos | `["show version", "reload now"]` | EXEC_ARBITRARY | second command fails `blocklist` | | EXEC_ARBITRARY | profile |
| ntunes `send_command` † | nxos | `show running-config \| section bgp` | EXEC_ARBITRARY | fail: `shell-meta` | | EXEC_ARBITRARY | profile |
| ntunes `send_command` | nxos | `show version > bootflash:v.txt` | EXEC_ARBITRARY | fail: `shell-meta` | | EXEC_ARBITRARY | profile |
| junos `execute_junos_command` † | junos | `show bgp summary \| no-more` | EXEC_ARBITRARY | fail: `shell-meta` | | EXEC_ARBITRARY | profile |
| junos `execute_junos_command` † | junos | `show configuration \| display set` | EXEC_ARBITRARY | fail: `shell-meta` | | EXEC_ARBITRARY | profile |
| junos `execute_junos_command` | junos | `request system reboot` | EXEC_ARBITRARY | fail: `blocklist` | | EXEC_ARBITRARY | profile |
| junos `execute_junos_pfe_command` | junos | `show jnh 0 exceptions` | EXEC_ARBITRARY | never downgraded | | EXEC_ARBITRARY | profile |
| junos `render_and_apply_j2_template` † | junos | `apply_config: false` | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| junos `load_and_commit_config` | junos | any | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| eos `push_config` † | eos | no `dry_run` given | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| eos `push_config` | eos | `dry_run: false` | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| mcfortigate `search_config` | fortios | `term: admin` | READ_CONFIG | n/a | | READ_CONFIG | profile |
| netdev `run_show_command` | fortios | `get system status` | READ_OPERATIONAL | n/a | no match | READ_OPERATIONAL | profile |
| ntunes `send_command` † | fortios | `show system interface` | EXEC_ARBITRARY | pass | match | READ_CONFIG | reclassify |
| ntunes `send_command` | panos | `show system info` | EXEC_ARBITRARY | pass | no match | READ_OPERATIONAL | downgrade |
| ntunes `send_command` | panos | `show config running` | EXEC_ARBITRARY | pass | match | READ_CONFIG | reclassify |
| meraki `execute_api` | other | `capability_id: getNetworkDevices` | via table | `^get` → READ_OPERATIONAL | | READ_OPERATIONAL | capability_table (M1-17) |
| meraki `execute_api` | other | `capability_id: rebootDevice` | via table | `^reboot` → WRITE_CONFIG | | WRITE_CONFIG | capability_table (M1-17) |
| clab `destroyLab` | n/a | any | LAB_LIFECYCLE | | | LAB_LIFECYCLE | profile |
| unknown server, tool `frobnicate` † | n/a | `{command: "show clock"}` | none | not run | | EXEC_ARBITRARY | fallback |

Design answers for the † rows:

- The four pipe rows: the design allows output filters (section 5.6) and gives `READ_OPERATIONAL` (downgrade) or `READ_CONFIG` (reclassify). The code refuses every pipe, so they stay `EXEC_ARBITRARY`.
- `render_and_apply_j2_template` with `apply_config: false` and `push_config` without `dry_run`: the design gives `READ_CONFIG` (source `dry-run`) through section 7, which is M3.
- FortiOS `show system interface`: the design gives `EXEC_ARBITRARY`, because on FortiOS `show` prints configuration and is not on the FortiOS allow-list; the correct path is `get system interface` or a typed config tool. The code does not know the vendor and lets `show` through. For this command the `system interface` keywords make the call `READ_CONFIG`, but most FortiOS `show` commands (`show vpn ipsec phase1-interface`, `show user local`) come out `READ_OPERATIONAL`. That is looser than the design, which is accepted and open until the vendor reaches `Classify`. Until then, M2 redaction on every result, whatever the class, is the mitigation (section 2). None of these commands is a write.
- `frobnicate`: the design runs the section 3 fallback classifier and downgrades to `READ_OPERATIONAL` with `profile_gap`. The code has no fallback classifier; a tool missing from the profile is `EXEC_ARBITRARY`.

## 10. Test expectations

Tier 1 table tests in `internal/classify` cover every row in section 9 except the two Meraki rows, which arrive with capability tables (M1-17): `classify_test.go` (`TestWorkedExamples`, `TestExitCriterion3` for M1 exit criterion 3 and test-matrix rows 3 and 5, the allow-prefix, blocklist and config-read tables with one positive and one negative case per entry, and the chaining and injection forms the downgrade never accepts) and `security_test.go` (the multi-line injection regressions from the security review of PR #150, with every line-break variant, through every free-form tool; the short-form config dumps of the PR #152 review; shell-quoted option injection; the 1024-byte cap; `monitor traffic` without `count`). Each vendor allow-list and blocklist entry of sections 5.6 and 6.1 gets its cases when the vendor tables are implemented.

There is no `classify/rules.yaml`. `tools/policy-lint` validates the policy schema only; it does not classify commands, so there is no second implementation to keep in step, and the Go regexes in `internal/classify/command.go` are the only copy. If a Python consumer of the command rules appears, `fathomgate` should export them from the Go source rather than load a hand-kept file (M1-24 reconciles this section).
