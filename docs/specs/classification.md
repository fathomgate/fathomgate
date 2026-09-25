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

1. Look up `tool` in the profile. If found, take `class` and `class_source: profile`. If the tool has `capability_param` (a planned profile field, see [profile-schema.md](profile-schema.md#3-planned-fields-not-yet-parsed)), resolve through the capability table (`class_source: capability_table`). If the tool has `config_params` and its class is not `EXEC_ARBITRARY`, run the config payload check (section 11); a failure sets `EXEC_ARBITRARY` with `class_source: reclassify` and ends classification, so no later step can lower it.
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
| `reclassify` | The arguments moved the class anywhere else: an `EXEC_ARBITRARY` or `READ_OPERATIONAL` call whose commands read configuration is `READ_CONFIG` (section 6), a `READ_OPERATIONAL` call whose command fails section 5 is `EXEC_ARBITRARY` (defence in depth against a server whose own filter is weaker than its tool name), and a call whose config payload fails section 11 is `EXEC_ARBITRARY`. | yes |
| `capability_table` | Step 1 through a capability table. | no, M1-17 |
| `annotation_raise` | Step 3 raised a read class to `EXEC_ARBITRARY`; a raised tool is never downgraded (section 4). | by `internal/gate`, not by `Classify` |

What the code does not do yet: step 2 has no fallback classifier (section 3), so a tool missing from the profile is `EXEC_ARBITRARY` and is never downgraded; step 3 runs in `internal/gate`, not in `Classify` (section 4); step 6 is M3 (section 7). The first and last are stricter than the design.

The code is looser than the design in one place: it does not know the vendor, so a FortiOS `show` whose second word is not a config keyword (`show vpn ipsec phase1-interface`, `show user local`, both carrying `ENC` secrets) is `READ_OPERATIONAL` where the design's FortiOS allow-list makes it `EXEC_ARBITRARY`. The same holds on every vendor for operational commands that print secrets (IOS and NX-OS `show snmp community`, `show key chain`, `show crypto isakmp key`). This is accepted and open until the vendor reaches `Classify`, which needs a decision record. Until then the mitigation depends on M2: redaction MUST run on every tool result, whatever the class and whether or not a rule carries the `redact` obligation (invariant 4), not only on `READ_CONFIG` calls.

`Result.Reason` never contains agent-supplied text: a failed command is named by its 1-based index and the check (`command 2 failed the read allow-list (blocklist)`), a failed config line by its element and line (`config element 1 line 2 failed the config payload check (escape-word)`), and an unknown tool is "tool not in profile" (the tool name is in the structured request). The `never-downgrade` token (section 8) is matched case-insensitively.

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
| `destructiveHint: true` on a tool classed `READ_OPERATIONAL`, `READ_CONFIG` or `INVENTORY_READ` | Same |
| `readOnlyHint: true` on anything | No effect |
| `destructiveHint: false` on anything | No effect |

Annotations are untrusted by the spec. They are used only in the direction that cannot be abused by a malicious server.

`internal/gate` applies this table (ADR 0026 step 3); `Classify` itself has no annotation input. The test is on the profile's class. A raised call is `EXEC_ARBITRARY` with `class_source: annotation_raise`, whatever its commands say: the upstream is saying the tool's execution context is not read-only, so a raised tool is never downgraded (as if its notes carried `never-downgrade`, section 8). The raise can only make a class stricter. A call whose commands already made it `EXEC_ARBITRARY` keeps its own `class_source`, and a raise never re-runs the downgrade: re-running it once turned a raised `READ_CONFIG` tool with `show version` into `READ_OPERATIONAL` (security review of PR #162, H1). An annotation is taken as sent: the gate's input distinguishes an absent annotation from an explicit `false` or `true`, and only the explicit value counts. go-sdk decodes an absent `readOnlyHint` as `false`, so how the proxy maps go-sdk's `ToolAnnotations` onto that input is decided in the wiring task (M1-19). The zero-target rule of [profile-schema section 2.2](profile-schema.md#22-targets-at-the-gate) exempts a tool by its profile class, so a raised `INVENTORY_READ` tool is decided by the rules as `EXEC_ARBITRARY`.

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
| `monitor-no-count` | Junos `monitor traffic` without a `count`, or with any `count` not followed by `n` from 1 to 1000 (every `count` is checked, so `count 5 count 999999` fails in either order); without it the capture runs until interrupted (section 5.6). |
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
(?:^|\s)(?:configure|conf(?:i(?:g(?:u(?:re?)?)?)?)?\s+t(?:e(?:r(?:m(?:i(?:n(?:al?)?)?)?)?)?)?|edit|set|delete|rollback|commit|wr(?:i(?:te?)?)?|write-file|read-file|copy|rel(?:o(?:ad?)?)?|reboot|shutdown|clear|reset|format|erase|debug|undebug|request\s+system|zeroize|admin\s+(?:save|reboot)|tclsh|bash|python|guestshell|start\s+shell)(?:\s|$)
```

`write-file` and `read-file` are the Junos `monitor traffic` options that write a capture to disk and read one back from a file on the device.

The expression above is the specification of the anywhere list. The code does not run it: since M1-39 it looks each word of the normalised command up in a set of the single-word verbs, and each two consecutive words up as the two-word verbs (`blocked` in `internal/classify/command.go`), because the unanchored expression cost about 60 µs per KiB of command. The tests keep the expression and check that both give the same answer on every normalised command (`TestBlocklistWordsMatchRegexp`, `FuzzBlocklistWords`), and hold the whole of `classifyCommand` to a frozen copy on the old expressions, class and check id (`TestClassifyCommandMatchesOld`, `FuzzClassifyCommandMatchesOld`). A change to the list changes both.

The lists fail closed, and some reads fail with them. Known and accepted (security review of PR #152): `show debug`, Junos `show system commit`, `show system rollback` spelled in full, `show configuration commit list` and any show argument that is a blocklisted word stay `EXEC_ARBITRARY`.

### 5.4 Pipe and redirect ban

Every `|`, `<`, `>`, `;`, `&` and backtick fails, including the output filters section 5.6 would allow (`| json`, `| no-more`, `| section bgp`, `| display set`). This is stricter than the design; an agent that needs a filter uses a typed tool or asks for the unfiltered command.

`"`, `'`, backslash, `{`, `}`, `*`, `?`, `[`, `]`, `~` and `$` fail too. On a server whose command reaches a shell on its own host, they rebuild what the leading-dash check looks for: `ping 1.1.1.1 "-f"`, `'-f'` and a backslash-escaped `-f` become `-f`, `ping {-f,1.1.1.1}` is brace-expanded, `[-]f`, `*` and `?` are globbed, `~root` is a home directory, and `$'...'`, `$HOME`, `$(...)` and `${IFS}` are rewritten. A `$` at the end of a word (followed by a space or the end of the line) is allowed: no shell expands it, and it is the regex anchor in IOS `show ip bgp regexp _65000$`.

The check is the RE2 expression ``[|<>;&"'{}*?\[\]~`\x5c]|\$\S`` run as a byte loop (`hasShellMeta`, M1-39); `TestShellMetaMatchesRegexp` and `FuzzShellMeta` check the loop against the expression on any string.

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

Examples: eos-mcp `push_config` with no `dry_run` argument (default true) is `READ_CONFIG`; ntunes `send_config` with `dry_run: true` is `READ_CONFIG`.

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
| junos `render_and_apply_j2_template` | junos | `apply_config: false` | EXEC_ARBITRARY | never downgraded (unsandboxed Jinja2, M1-35) | | EXEC_ARBITRARY | profile |
| junos `load_and_commit_config` | junos | `set system host-name x` | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| junos `load_and_commit_config` | junos | `set system host-name x`, then a line `run request system reboot` | WRITE_CONFIG | line 2 fails `set-verb` (section 11) | | EXEC_ARBITRARY | reclassify |
| junos `load_and_commit_config` | junos | `config_format: text`, `system { commit { ... } }` | WRITE_CONFIG | data: bytes only (section 11) | | WRITE_CONFIG | profile |
| eos `push_config` † | eos | no `dry_run` given | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| eos `push_config` | eos | `dry_run: false` | WRITE_CONFIG | n/a | | WRITE_CONFIG | profile |
| eos `push_config` | eos | `config_lines: ["end", "reload now"]` | WRITE_CONFIG | element 1 fails `escape-word` (section 11) | | EXEC_ARBITRARY | reclassify |
| upa `set_config_commands_and_commit_or_save` | ios | `commands: ["interface Gi1", " description uplink"]` | WRITE_CONFIG | passes section 11 | | WRITE_CONFIG | profile |
| ntunes `send_config` | nxos | `config_commands` element `hostname x`, line break, `end` | WRITE_CONFIG | line 2 of element 1 fails `escape-word` | | EXEC_ARBITRARY | reclassify |
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
- `push_config` without `dry_run`: the design gives `READ_CONFIG` (source `dry-run`) through section 7, which is M3. junos `render_and_apply_j2_template` is no longer a dry-run candidate: the upstream renders the agent's `template_content` in an unsandboxed Jinja2 environment before it reads `apply_config` (`jmcp.py:1369-1375` at `75fe90a`), so a template runs Python on the MCP host. Its profile class is `EXEC_ARBITRARY` with `never-downgrade` (M1-35, security review of PR #161).
- FortiOS `show system interface`: the design gives `EXEC_ARBITRARY`, because on FortiOS `show` prints configuration and is not on the FortiOS allow-list; the correct path is `get system interface` or a typed config tool. The code does not know the vendor and lets `show` through. For this command the `system interface` keywords make the call `READ_CONFIG`, but most FortiOS `show` commands (`show vpn ipsec phase1-interface`, `show user local`) come out `READ_OPERATIONAL`. That is looser than the design, which is accepted and open until the vendor reaches `Classify`. Until then, M2 redaction on every result, whatever the class, is the mitigation (section 2). None of these commands is a write.
- `frobnicate`: the design runs the section 3 fallback classifier and downgrades to `READ_OPERATIONAL` with `profile_gap`. The code has no fallback classifier; a tool missing from the profile is `EXEC_ARBITRARY`.

## 10. Test expectations

Tier 1 table tests in `internal/classify` cover every row in section 9 except the two Meraki rows, which arrive with capability tables (M1-17): `classify_test.go` (`TestWorkedExamples`, `TestExitCriterion3` for M1 exit criterion 3 and test-matrix rows 3 and 5, the allow-prefix, blocklist and config-read tables with one positive and one negative case per entry, and the chaining and injection forms the downgrade never accepts) and `security_test.go` (the multi-line injection regressions from the security review of PR #150, with every line-break variant, through every free-form tool; the short-form config dumps of the PR #152 review; shell-quoted option injection; the 1024-byte cap; `monitor traffic` without `count`; and for section 11, the PR #158 session-escape payloads through every CLI config tool of the shipped profiles in `TestSecurityConfigSessionEscape`, every escape word and each of its abbreviations in `TestSecurityConfigEscapeWords`, ordinary configuration that must stay `WRITE_CONFIG` in `TestConfigLinesThatStayWrites`, the Junos load formats in `TestSecurityJunosLoadConfig`, the union default in `TestConfigDialectDefaultsToUnion` and JSON-string payloads in `TestSecurityConfigEscapeAsJSONString`). `internal/gate` `TestConfigSessionEscape` carries the lab-open reproduction from arguments to decision. Each vendor allow-list and blocklist entry of sections 5.6 and 6.1 gets its cases when the vendor tables are implemented.

There is no `classify/rules.yaml`. `tools/policy-lint` validates the policy schema only; it does not classify commands, so there is no second implementation to keep in step, and the Go rules in `internal/classify/command.go` are the only copy. If a Python consumer of the command rules appears, `fathomgate` should export them from the Go source rather than load a hand-kept file (M1-24 reconciles this section).

## 11. Config payload checks

A config payload reaches the device in configuration mode, and nothing in most upstreams keeps it there. eos-mcp `push_config` puts every `config_lines` element into the same eAPI call as `configure session <name>` (`eapi.py:118-143` at `bffb893`); netmiko `send_config_set` (upa `set_config_commands_and_commit_or_save`, ntunes `send_config` and `send_config_parallel`) writes each line to the CLI. A line such as `end`, followed by `reload now`, or by `configure` and `hostname x`, runs outside the configuration session: the call is an exec command, or a write with no commit timer, not the `WRITE_CONFIG` its tool says (security review of PR #158, M1-36). EOS also runs exec commands from configuration mode without any exit, and some configuration schedules execution itself.

So every call to a tool with `config_params` whose class is not already `EXEC_ARBITRARY` is checked, element by element and line by line, before any command rule (section 2, step 1). A failure makes the call `EXEC_ARBITRARY` with `class_source: reclassify`; `Result.Reason` names the element, the line and the check, never the text. A tool that is already `EXEC_ARBITRARY` (junos `render_and_apply_j2_template`) has nothing to raise and is not checked.

### 11.1 Lines

The whole payload, every element of every config argument together, may be at most 64 KiB (65536 bytes), the gate's cap on a call's arguments (check `too-long`, reason `config payload failed the config payload check (too-long)`). Then every element, in profile order, is split into lines on CRLF, CR and LF, and each line is checked. Every other line separator stays in the line and fails the byte check. Per line, in this order:

| Check id | Fails when |
| --- | --- |
| `too-long` | CLI and Junos set dialects: the line is longer than 1024 bytes, the command cap of section 5. No configuration statement needs more. Junos text and xml lines have no line cap, as an xml document can be one line. |
| `control-character` | The line holds a byte below `0x20` other than tab, or `0x7f`: vertical tab, form feed, NUL, Ctrl-C, Ctrl-Z (which ends configuration mode on IOS), escape, the file, group and record separators. |
| `non-ascii` | The line holds a byte of `0x80` or above: NEL, U+2028, U+2029, no-break space, fullwidth look-alikes. A description in UTF-8 fails too; accepted. |
| `separator` | CLI dialect: the line holds `;`, comment lines included (`! x ; reload` is a comment to IOS but two commands to NX-OS, so this check runs before blank and comment lines pass). NX-OS runs `hostname x ; end ; reload` as three commands (security review of PR #170, H1). A `;` in a description or banner fails too; accepted. |
| `leading-symbol` | CLI dialect: after trimming spaces and tabs, the line starts with anything but a letter, a digit or `!`. Blank lines and `!` comments pass. |
| `escape-word` | CLI dialect: the first word (letters, digits, `-` and `_`, case-insensitive) is a non-empty prefix of an escape word (11.2). |
| `set-verb` | Junos set dialect: the first word (up to a space or tab, case-insensitive) is not exactly one of the set statements, or `top` or `up` carries anything but an optional count after `up` (11.3). Blank lines and `#` comments pass. |
| `exec-config` | CLI dialect: any word of the line, trimmed of characters outside `[a-z0-9-]` at both ends, is a prefix of `autocommand` at least 5 characters long (`autoc`), in any position (11.2). Junos: configuration that runs something (11.3). |
| `dtd` | Junos xml: the line holds `<!`, a DOCTYPE or entity declaration. |

The prefix test is one-way, as vendor CLIs accept abbreviations: `e`, `en`, `conf`, `wr`, `rel` and `sh` fail, while a longer word such as `exit-address-family`, `load-interval`, `exec-timeout`, `event-monitor` or `shutdown` is not a prefix of any escape word and passes. Punctuation ends the word, so `end!` is `end`.

### 11.2 CLI dialect: the union list

The CLI dialect applies to every tool that 11.4 does not name, and so to any profile the classifier cannot tie to a vendor. It is the union of what leaves configuration mode on EOS, IOS, IOS-XE, NX-OS, IOS-XR, Junos, PAN-OS and Huawei VRP through netmiko, of the exec commands EOS runs from configuration mode, and of configuration that defines an exec word or schedules execution. NX-OS is reached through netmiko `cisco_nxos` by upa and ntunes, which is why `;` fails (11.1).

| Group | Words |
| --- | --- |
| Leave or re-enter configuration mode, end the session | `end`, `exit`, `quit`, `abort`, `configure` (so `conf`, `config`, `configure session other`, `configure terminal`, `configure replace`), `commit` (commits an EOS session at once, with no timer), `rollback`, `return` and `system-view` (Huawei VRP), `admin` (IOS-XR) |
| Exec from configuration mode, shells and interpreters | `do`, `run`, `exec`, `execute`, `enable`, `disable`, `bash`, `shell`, `start`, `tclsh`, `python`, `python3`, `guestshell`, `op` |
| Device state, files, reboots | `reload`, `reboot`, `halt`, `reset`, `restart`, `zeroize`, `zerotouch`, `copy`, `write`, `delete`, `erase`, `format`, `rename`, `mkdir`, `rmdir`, `clear`, `request`, `load`, `save`, `install`, `diagnose`, `debug`, `undebug`, `test`, `tcpdump` |
| Other exec verbs EOS runs from configuration mode | `ping`, `traceroute`, `clock` (`clock set`), `send`, `watch`, `logout`, `terminal`, `agent` |
| Reads | `show`, `more`. A write needs no read. EOS runs `show` inside a session, so its output (with any secrets in it) would ride on a write's result, and `show ... \| redirect` writes a file; on the other platforms `show` is not valid in configuration mode. Decided the same for every vendor. |
| Sessions to other hosts | `ssh`, `telnet`, `connect`: the lines after one go to the other host. |
| Aliases | `alias`, `cli`: IOS `alias configure hn do reload`, EOS `alias hn reload now` and NX-OS `cli alias name hn reload` define an exec word that a later call (`["hn", ""]`, the blank line confirming) uses as an ordinary line (security review of PR #170, H2). |
| Scheduled execution | `event` (IOS EEM `event manager`), `event-handler`, `schedule`, `scheduler`, `kron`, `daemon`, `command`: configuration that runs a command or a process later, or at once (H3). |
| Login autocommand, any word position (check `exec-config`) | `autocommand` and its abbreviations of 5 or more characters: `line vty 0 15` then ` autocommand reload`, or `username netops autocommand reload`, runs `reload` at the next login, and upa, ntunes and netdev-ssh-mcp open a new session per call, so the agent's next read would run it (security review of PR #170 round 2, R2-H1). `auto`, `auto-cost` and `autocommand-options` pass. |

Accepted costs, all in the stricter direction: `exit` from a sub-mode (write flat configuration; the parser returns to global mode by itself), `enable secret` and `enable password`, `clock timezone`, `system mtu` (`system` abbreviates `system-view`), NX-OS `install feature-set`, through netmiko the Junos and PAN-OS `delete`, `copy` and `rename` statements, all FortiOS configuration (`config ...` and `end`), and any line holding `;` are `EXEC_ARBITRARY`. A policy that must allow one allows `EXEC_ARBITRARY` for that tool and target explicitly, or the agent uses a typed tool.

Which list applies, per profile:

| Profile | Tool (argument) | Dialect | Why |
| --- | --- | --- | --- |
| `eos-mcp` | `push_config` (`config_lines`) | CLI, the union | eAPI switches mode on `end`, `exit`, `abort` and `configure`, and EOS runs exec commands from configuration mode, so every exec word matters even without an exit. |
| `upa` | `set_config_commands_and_commit_or_save` (`commands`) | CLI, the union | netmiko on whatever platform the upstream's inventory names, NX-OS included; the vendor is not known at classification. |
| `ntunes-netmiko-mcp-server` | `send_config`, `send_config_parallel` (`config_commands`) | CLI, the union | As upa. `enter_config_mode` is refused (ADR 0033), so the lines are always sent in configuration mode. |
| `junos-mcp-server` | `load_and_commit_config` (`config_text`) | Junos load (11.3) | PyEZ `Config.load` over NETCONF, not a CLI. |
| `junos-mcp-server` | `render_and_apply_j2_template` | not checked | Already `EXEC_ARBITRARY` and never downgraded. |
| `netdev-ssh-mcp` | none | | No config arguments. |
| any other | any | CLI, the union | Stricter. |

### 11.3 Junos load

junos-mcp-server `load_and_commit_config` reads `config_format` (default `set`), lower-cases it and calls PyEZ `Config.load(config_text, format=...)` for `set`, `text` or `xml` (`jmcp.py:1658` and `1683-1685` at `75fe90a`), then commits itself. The format counts as `text` or `xml` only when `config_format` is an ASCII string that lower-cases to one of them, so no Unicode case folding can make Go and Python disagree; anything else, including an absent `config_format`, gets the set rules.

Configuration that runs something is `EXEC_ARBITRARY` in every format (security review of PR #170, H3): event policies (`event-options`, `execute-commands`), commit, op and event scripts (`scripts`) and on-box extensions (`extensions`).

- `set`, the default: the payload is configuration-mode statements (`<configuration-set>`). Whether the RPC acts on `run`, `commit`, `rollback`, `load`, `save`, `exit` or `quit` in a set payload is not established from source, so the default is conservative, an allow-list: every line starts with exactly one of `set`, `delete`, `activate`, `deactivate`, `annotate`, `insert`, `rename`, `copy`, `protect`, `unprotect`, `edit`, `top`, `up`. Abbreviations (`se`) fail, and so does a text-format payload sent without `config_format: text`. `top` must stand alone and `up` may carry only a count: Junos runs `top <command>` and `up <n> <command>` as `<command>` at that level, so `top run request system reboot` fails `set-verb` (M2). A line fails `exec-config` when any word after the first, trimmed of every character outside `[a-z0-9-]` at both ends (quotes, backslashes, brackets: `set event-options\ x`), is a non-empty prefix of one of the four hierarchy names: Junos accepts unique abbreviations (`set event-o ...`), and `edit system` then `set scripts ...` names the hierarchy relative to the current level, so a token test catches what a full-path test would miss. Accepted cost: a one-letter word anywhere after the first abbreviates a hierarchy name, so `set interfaces ge-0/0/0 description e` and `set policy-options policy-statement s ...` are `EXEC_ARBITRARY`; choose a longer name.
- `text` and `xml`: the payload is configuration data. The `load-configuration` RPC parses a hierarchy (`<configuration-text>`) or an XML tree, and PyEZ builds the RPC from elements, not by joining strings, so no statement runs a command, and a hierarchy named `commit`, `file` or `disable` is just configuration. The byte checks apply, a line fails `exec-config` when it holds one of the four hierarchy names as a case-insensitive substring (otherwise `config_format: text` would be the bypass), and an xml line fails `dtd` on `<!`. Open pending tier 2 (M1-28 on vMX or cRPD): whether a text load accepts an abbreviated hierarchy (`system { scr { op { file x; } } }`). If it does, text payloads are to be tokenised and given the set-format prefix test.

### 11.4 Dialect table

`configDialects` in `internal/classify/config.go` chooses the dialect by the profile's `server` and the bare tool name; only `junos-mcp-server` `load_and_commit_config` is not CLI. The gate refuses a profile whose `server` is not the `--server` name, so another upstream cannot borrow the key, and a Junos profile under another name gets the union, the stricter list. Moving the dialect into the profile schema is a schema change and needs a decision record.

### 11.5 Not covered

- The CLI list is a denylist, and EOS configuration mode accepts every exec command, so for eos-mcp `push_config` it cannot be complete: an EOS exec verb missing from 11.2 still passes. The long-term fix is an allow-list of top-level configuration words for `push_config` (open; threat model). Tier 2 on cEOS (M1-28) checks the verbs added in the PR #170 review, `clock set` and `watch` among them.
- Configuration that persists access or locks operators out stays `WRITE_CONFIG`: `username ... privilege 15 ... nopassword`, `aaa authorization exec default none`, `management api http-commands`, Junos `set system login user ... class super-user`, `boot system`. It is a write, held on production and allowed on lab devices by design; the threat model records it.
- An alias an operator configured on the device before Fathomgate saw it turns an ordinary-looking line into an exec command. Accepted (threat model).
- IOS `menu m command 1 reload` defines a menu whose entry runs a command, but a menu is reached only through an exec command (`menu m`) that 11.2 already fails, or an autocommand, which fails `exec-config`. EOS `username ... shell` changes what later logins land in. Both stay `WRITE_CONFIG`; accepted (threat model).
- netmiko `linux` and generic device types run every line as a shell command. Do not put shell hosts in the inventory behind upa or ntunes.
- JSON strings: FastMCP runs `json.loads` on a string sent for a `list[str]` parameter (`config_lines`, `commands`, `config_commands`). `CheckArguments` reports a valid JSON array as malformed (M1-35), and the CLI dialect also fails it on `leading-symbol`. A JSON object decodes to a dict, which the upstream's `list[str]` validation refuses. junos `config_text` goes as a plain string to a low-level server that does not pre-parse.
- Whether EOS runs a line after `end` inside one eAPI call is not proved on a device yet; tier 2 on cEOS (M1-28) shows it. The check does not depend on the answer.
