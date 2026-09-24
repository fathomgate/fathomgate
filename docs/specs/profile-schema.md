# Profile schema

Normative specification for the per-upstream-server profile. A profile tells `internal/classify` which class each tool has and where the target, command and configuration payload live in each tool's arguments. One YAML file per upstream server lives in `profiles/`. Profiles are data; adding one needs no Go.

This document describes what `internal/classify/profile.go` and `normalize.go` parse. The loader is strict: a key not listed in sections 1 or 2 is a load error. Fields the plan calls for but the loader does not yet accept are listed in section 3 and MUST NOT appear in a profile today. Decision record: [ADR 0010](../adr/0010-classify-by-payload-not-annotations.md). Companion: [classification.md](classification.md), [inventory-schema.md](inventory-schema.md).

## 1. Top-level fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `server` | string, non-empty | yes | Short name used as the tool prefix toward the agent (`netdev-ssh-mcp.get_config`) and in policy `match.servers`. MUST be unique across the `profiles/` directory; `LoadProfileDir` rejects duplicates. To be usable as a prefix it MUST match `[A-Za-z0-9_-]+` ([section 8](#8-proxy-config-m0)); every shipped profile does. |
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
| `transport`, `era`, `vendor_hint`, `verified_version` | Launch and era configuration; today the launch command lives in `netguard serve` flags ([section 8](#8-proxy-config-m0)). | M2 |

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

## 8. Proxy config (M0)

There is no separate proxy spec yet; this section is normative for `internal/proxy` and `netguard serve` until one exists. Decision record: [ADR 0012](../adr/0012-serve-cli-and-proxy-api-for-m0.md) (accepted).

### 8.1 Tool-name prefixing

- Every upstream tool is exposed to the agent as `<server>.<tool>`, where `<server>` is the upstream's `server` key from this schema (section 1), passed to the proxy explicitly. It is never derived from the upstream binary name.
- `<server>` MUST match `[A-Za-z0-9_-]+` and MUST NOT read as `netguard`: a name that equals `netguard` once lower-cased, stripped of `-` and `_` and stripped of trailing digits (`NetGuard`, `net-guard`, `net_guard2`) is reserved, so no upstream prompt can carry a label that reads `[from netguard]`. It contains no `.`, so the first `.` in a prefixed name always ends the prefix, and upstream tool names that contain dots (`s.a.b` is tool `a.b` on server `s`) route unambiguously.
- `tools/call` splits the name at the first `.`, looks up the upstream by `<server>` and forwards the unprefixed `<tool>` with the agent's arguments unchanged. `_meta` from the agent is never forwarded; what does cross is in 8.4.
- An upstream tool name outside the MCP tool-name character set `[A-Za-z0-9_.-]`, or one whose prefixed name exceeds 128 characters, is not exposed and is logged. So is a tool whose `inputSchema` is not a JSON object with `"type": "object"`.
- Two upstreams with the same `<server>`, or one upstream listing the same tool name twice, is a startup error.
- Title, description, input and output schema and annotations pass through unchanged. They are untrusted data: annotations are never used to decide anything, and descriptions are pinned from M2. Tool `_meta` and `icons` are dropped.
- The tool list is read once at startup. `notifications/tools/list_changed` from an upstream is not followed, and the proxy advertises `tools` without `listChanged`.

### 8.2 Errors toward the agent

| Situation | Wire form |
| --- | --- |
| Name has no `.`, or an empty side | JSON-RPC error `-32602`, `data: {"tool": "<name>", "reason": "unprefixed", "servers": [...]}` |
| Prefix names no configured upstream | `-32602`, `reason: "unknown_server"` |
| Upstream has no such tool (or it was not exposed, 8.1) | `-32602`, `reason: "unknown_tool"` |
| Upstream returns a JSON-RPC error | Code kept if it is `-32700`, `-32600`, `-32601` or `-32603`; any other code, including `-32602` (reserved for the rows above), becomes `-32603`. Message `upstream <server>: <upstream message>`, with C0 and C1 control characters (including ESC and newline), DEL, Unicode format characters (Cf: bidi controls U+202A–U+202E and U+2066–U+2069, zero-width space U+200B, BOM), the separators U+2028 and U+2029, and invalid UTF-8 escaped as `\uXXXX` text, every backslash `\` doubled to `\\` (so any `\u` in the output is netguard's own escape: upstream text cannot spell one that a decoding reader would turn into a newline), and the upstream part capped at 512 bytes plus an ellipsis (`...`). Every relayed upstream string in section 8 is escaped this way. Upstream `data` dropped |
| Upstream result, including `isError: true` | `content`, `structuredContent` and `isError` forwarded unchanged; the result's `_meta`, and any `requestState` or `inputRequests` on a complete result, dropped (8.4) |
| Upstream asks for form elicitation and the agent declared form elicitation | Relayed with the origin label (8.4): `input_required` to a stateless agent, `elicitation/create` to a stateful one |
| Upstream asks for sampling, roots or URL-mode elicitation; or a schema, message, id or count outside 8.4 (including any text that reads as an origin label); or the agent did not declare form elicitation; or more than 10 rounds or 10 prompts in the call | Tool result `isError: true`, text `netguard refused an input request (<kind>) from upstream <server> during <tool>: <reason>`. The reason is fixed text: it never quotes an upstream value (a type, name or string), only what was expected. The upstream's prompt is not shown |
| Stateful upstream sends `elicitation/create` while a stateless agent is calling ([ADR 0014](../adr/0014-stateful-upstream-prompts-to-stateless-agents.md)), while another of this call's prompts is open (on any path), or after 10 prompts in this call | The upstream gets a JSON-RPC error. The agent gets the refusal text above in place of the upstream's error if the upstream then fails the call, or appended to the upstream's result if it completes |
| Stateful upstream sends `elicitation/create` while zero or several calls to it are in flight | The upstream gets a JSON-RPC error. The refusal (`netguard refused an input request (elicitation) from upstream <server>: it cannot be attributed to one call (<n> in flight)`) is appended to the result of every call then in flight; it never replaces an upstream error or result |
| Agent calls a method of a capability the proxy does not declare (`prompts/list`, `prompts/get`, `resources/list`, `resources/read`, `resources/templates/list`, `resources/subscribe`, `resources/unsubscribe`, `logging/setLevel`, `completion/complete`) | JSON-RPC error `-32601` in either era. The proxy declares `tools` only |
| Upstream `input_required` with no input requests (load shedding) | Tool result `isError: true`, text `upstream <server> is busy ...; retry <tool> later` |
| Agent retry with a `requestState` netguard did not issue, that fails authentication, has expired, or was issued for another tool or other arguments | `-32602`, `data: {"tool": "<name>", "reason": "invalid_request_state", "detail": "..."}`. Nothing reaches the upstream |
| Agent retry answering an outstanding input request with a non-elicitation result, or with an action other than `accept`, `decline` or `cancel` | `-32602`, `reason: "invalid_input_responses"`. Nothing reaches the upstream |
| Agent sends `inputResponses` without a `requestState` | Not an error (SEP-2322: ignore what is not recognised). The answers are cleared before the call reaches `Proxy.dispatch`, so no M1 stage sees them, and never forwarded, and the call goes up as a first call, so an upstream that needs input asks again and the agent gets that prompt relabelled (8.4). netguard forwards only answers to prompts it relayed, bound by its `requestState` |
| Agent retry with a valid `requestState` and answers to ids that are not outstanding | Those answers are ignored and never forwarded; the others cross. With none left, the upstream gets its own `requestState` and no answers, and decides whether to ask again |
| Upstream process has exited, or exits mid-call | Tool result `isError: true`, text `upstream <server> is not running; restart netguard serve`. After a failed call the proxy waits up to 2 seconds to see the exit before choosing this text |

None of these is a policy decision, so none uses `allow`, `hold`, `deny` or `expired`. Policy denials arrive in M1 as tool errors that name the rule id ([ARCHITECTURE.md](../../ARCHITECTURE.md#pipeline)).

### 8.3 `netguard serve` flags

```text
netguard serve --server <name> --upstream <path> [--upstream-env KEY=VALUE]... [-- <upstream args>...]
```

| Flag | Meaning |
| --- | --- |
| `--server` | Required. The tool prefix: the upstream's profile `server` key (`netdev-ssh-mcp`). Validated against 8.1 before anything is spawned; an invalid name exits 2. |
| `--upstream` | Required. The upstream executable, spawned over stdio. An empty or blank value, or `--`, exits 2. A bare name is looked up on the proxy's `PATH`; MCP hosts that launch with an empty `PATH` need an absolute path. Arguments for it are accepted only after `--` and are passed verbatim, with no shell. A positional argument without a preceding `--` exits 2. |
| `--upstream-env` | Repeatable `KEY=VALUE` with `KEY` matching `[A-Za-z_][A-Za-z0-9_]*` (anything else exits 2), added after the inherited allow-list below, so it overrides. Upstream credentials go here; nothing from the agent is ever added. |
| `--policy`, `--inventory`, `--profiles`, `--audit` | Reserved. Refused with exit 2 in M0, because the pipeline they configure is not wired and M0 forwards every call. They are refused wherever they appear, including among the upstream arguments after `--`. |

Upstream environment: the upstream inherits only an allow-list from the proxy. On Unix that is `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR` and the POSIX locale categories `LC_ALL`, `LC_COLLATE`, `LC_CTYPE`, `LC_MESSAGES`, `LC_MONETARY`, `LC_NUMERIC` and `LC_TIME` (no wildcard), matched exactly. On Windows it is `PATH`, `SystemRoot`, `SystemDrive`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PATHEXT` and `COMSPEC`, matched ASCII case-insensitively (no Unicode case folding). Every other variable, including `NETGUARD_*`, reaches the upstream only through `--upstream-env`.

The agent side is stdio; stdout carries only the protocol. The upstream's stderr goes to the proxy's stderr one line at a time, each line prefixed `upstream <server>: ` with control characters escaped as in 8.2. A line longer than 4096 bytes is split at that limit, cut back to a whole UTF-8 character. A final line without a newline is written, prefixed and escaped the same way, when the upstream is closed. Startup (spawn, handshake, `tools/list`) has a 30-second limit. If it fails after the process started, the process is killed (the direct child only); when the upstream answers the handshake with an unsupported protocol version, go-sdk v1.8 first closes the session itself, so the child gets the shutdown grace below (5 seconds, then SIGTERM or kill) before it is reaped. A startup error printed to stderr has control characters escaped as in 8.2, since the upstream's JSON-RPC error message is part of it. On shutdown the upstream's stdin is closed, then it gets 5 seconds before SIGTERM and 5 more before it is killed (on Windows, killed after the first 5). Grandchildren, such as the server behind `uvx` or `npx`, are not signalled. Exit status: 0 when the agent disconnects or on SIGINT or SIGTERM, 1 when the upstream cannot be started or listed or the session fails, 2 for a usage error.

### 8.4 Protocol eras, `_meta` and input requests

Decision records: [ADR 0008](../adr/0008-dual-era-mcp-support.md) (accepted) and [ADR 0014](../adr/0014-stateful-upstream-prompts-to-stateless-agents.md) (accepted). The stateful era is 2025-11-25 and older (initialize handshake, session, server-initiated requests); the stateless era is 2026-07-28 (every request self-describing in `_meta`, MRTR).

**Era detection.** Each side is detected on its own, and the two need not match.

- Upstream, once at connect: go-sdk sends `server/discover` and, if the upstream answers with any error or names no stateless version, falls back to the initialise handshake at 2025-11-25 (and negotiates down to 2024-11-05). The negotiated version is logged with `upstream ready` as `protocol` and `era`.
- Agent, per request: from the initialise handshake for a stateful agent, from the request's `_meta` for a stateless one. go-sdk answers `server/discover` and `initialize` itself.
- Both versions travel with each call to the M1 pipeline seam (`Proxy.dispatch`), for the audit event.

**What the proxy advertises upstream.** netguard's own identity (`clientInfo` `netguard`), its own negotiated version and its own capabilities: form elicitation only. No roots, no sampling. Toward a stateless upstream go-sdk puts these in every request's `_meta`.

**`_meta`, agent to upstream.** Nothing of the agent's. The allow-list is empty: the agent's `_meta`, including the `io.modelcontextprotocol/` self-description, `progressToken` and any vendor key, is read (for era detection, and the progress token for the mapping below) and dropped. Forwarding it would present the agent's identity and capabilities as the proxy's (go-sdk does not overwrite keys already present). Adding a key needs a change to this section. The one key netguard sets itself is `progressToken`, with a token of its own (**Progress**, below).

**`_meta`, upstream to agent.** Nothing from results (`io.modelcontextprotocol/serverInfo` from an upstream could impersonate the proxy), tools (8.1), elicitation requests, progress notifications (below) or errors (8.2). Toward a stateless agent, go-sdk adds netguard's own `serverInfo`; a stateful agent gets no `io.modelcontextprotocol/` key at all. `_meta` inside individual content blocks still passes until redaction lands (M2).

**Upstream input requests.** Only form elicitation crosses to the agent, and only relabelled:

- The message becomes `[from <server>] ` followed by the upstream's message with control characters escaped as in 8.2 and capped at 2048 bytes.
- The requested schema is rebuilt from an allow-list, never copied. Root: `type` (`object`, or absent), `title` (prefixed `[from <server>] ` and escaped), `description` (escaped), `properties`, `required` (names of kept properties only). Property: `type` (`string`, `number`, `integer`, `boolean` or `array`), `title` (prefixed `[from <server>] ` and escaped; the property name when absent, so every field shows its origin), `description` (escaped), `enum`, `oneOf` (each option's `const` and escaped `title` only), `items` (arrays only: its `enum` and `type`), `minimum`, `maximum`, `minLength`, `maxLength`, `format` (only `email`, `uri`, `date` or `date-time`; any other value is dropped), `default` (a primitive or an array of them; since an accepted default goes back to the upstream as is, a string default that would need escaping, a backslash included, or is longer than 2048 bytes is dropped, and the human types the value). Everything else (`$defs`, `$ref`, `allOf`, `pattern`, `x-*`, `additionalProperties`, ...) is dropped.
- Origin-label spoofing: the prompt is refused if the message, the form title or description, a property name, title or description, a `oneOf` title, an `enum` or `const` value, or a default contains `[from` after folding: decoding, layer after layer, the backslash escapes `\uXXXX`, `\UXXXXXXXX`, `\xNN` and `\u{H..}`, HTML character references (decimal, hex, and `&lsqb;` `&lbrack;` `&rsqb;` `&rbrack;` `&amp;` `&lt;` `&gt;`, the `;` optional) and percent-encoding `%HH`, and counting text still changing after eight layers as a label; removing HTML tags and the markup punctuation `` * _ ` ~ < > / & | # `` and the backslash, so `[*from*` or `[<b>from</b>` reads as `[from` (false positives are accepted); removing white space, format characters (Cf), combining marks (Mn, Me) and the blank fillers U+115F, U+1160, U+3164, U+FFA0 and U+2800; lower-casing; fullwidth ASCII to ASCII; Latin small capitals and Cyrillic and Greek letters that look like Latin ones to those letters (among them а е о р с х і, ο ρ α), bracket look-alikes (`［ 【 〔 ⟦ ⁅ ❲ ⎡ ⌈ ﹇ 「 『` and others) to `[`. The fold is standard-library only, not NFKC or UTS #39 confusable detection: mathematical alphanumerics (U+1D400 block), precomposed accented letters that only NFD would split, superscript and circled letters, other scripts and font-specific homoglyphs pass it, and so do encodings it does not decode (other HTML named references, octal and named backslash escapes, quoted-printable, LaTeX, base64, and a label split across two fields). The label on the message, the form title and every property title is the second layer.
- The schema is also refused if its root `type` is not `object`, a property is not an object or has another type (nested objects included), an array property has no `items.enum`, an `enum` or `oneOf` has more than 64 entries or a value that is not a plain string, number or boolean (a string needing escaping, a control character or a backslash, cannot round-trip, so it is refused), a property name is empty, longer than 64 bytes or has a control character or a backslash (names are keys in the agent's answer, so they cross verbatim), there are more than 32 properties, the upstream schema exceeds 64 KiB or the rebuilt one 16 KiB.
- At most 16 input requests per result, each id 1 to 128 bytes with no control characters.
- The request's own `_meta` is dropped. URL-mode elicitation, sampling and roots are refused (8.2).

How the prompt reaches the agent, by era:

| Agent \ Upstream | Stateful (server-initiated `elicitation/create`) | Stateless (MRTR `input_required`) |
| --- | --- | --- |
| Stateful | Relayed as `elicitation/create` on the agent's session, attributed to the only call in flight on that upstream; refused when zero or several are in flight. go-sdk runs incoming upstream requests concurrently, so each call has one prompt slot, shared with netguard's own prompts to a stateful agent (next column): a prompt that arrives while another of the call's prompts is open is refused, and so is any past the 10th in the call. The agent's cancellation of the call cancels the prompt | netguard asks the agent with `elicitation/create`, one request at a time in id order, each taking the call's prompt slot, and retries the upstream with the answers and the upstream's `requestState`, up to 10 rounds and 10 prompts in the call; a round that would pass 10 prompts is refused before anything in it is asked |
| Stateless | Refused (ADR 0014; parking deferred to matrix row 17) | Returned as `input_required` with the relabelled requests and a netguard `requestState`; the agent's retry is verified and the upstream retried once per agent retry, up to 10 rounds and 10 prompts in the call (the count travels in the sealed `requestState`) |

**The agent's answer.** Only an elicitation result crosses back: `accept` with its `content`, or `decline` or `cancel` with nothing. Its `_meta` is dropped. A stateful agent's `accept` content is checked against the relabelled schema by go-sdk; a stateless agent's is left to the upstream.

**`requestState` toward a stateless agent.** netguard never hands out the upstream's `requestState`, in the clear or otherwise readable. It issues `ng2.<base64url(nonce || ciphertext)>`, sealed with AES-256-GCM under a random per-process key and a random 96-bit nonce, with the prefix as additional authenticated data. The ciphertext holds JSON with the upstream server, the unprefixed tool, a SHA-256 digest of the call's arguments (as sent, insignificant whitespace removed, so key order and duplicate keys count), the outstanding input request ids, the upstream's own `requestState`, the round, the prompts put to the human so far and an expiry 30 minutes out. The sealed length reveals roughly how large the upstream's state is; its content stays hidden. The upstream's state must be at most 64 KiB, and the sealed string at most 96 KiB: the proxy measures the sealed string before issuing it and refuses the prompt (tool error) rather than issue a state it would not accept back, and it refuses any incoming `requestState` longer than the same 96 KiB. On the retry netguard authenticates and decrypts it, checks the expiry, server, tool and argument digest, drops answers to ids that are not outstanding, checks every remaining answer against the allow-list above, and only then sends the upstream its own `requestState` and the cleaned answers. `inputResponses` that arrive without a `requestState` are ignored and the call goes up as a first call (8.2). A restart invalidates every outstanding `requestState`; the agent calls again without one.

**Progress.** When the agent's `tools/call` carries a `progressToken` that is a string, or an integer of magnitude at most 2^53-1 (JavaScript's `Number.MAX_SAFE_INTEGER`; a larger one may have been rounded on the way in, and anything else is ignored), netguard gives the upstream call a token of its own: 128 random bits as 26 base32 characters, new for every agent request (so for every MRTR retry too) and kept across the rounds netguard runs within one. The agent's token never goes upstream. Without one, the upstream is sent no token. While the call is open, an upstream `notifications/progress` naming netguard's token becomes netguard's own notification to the agent, built from:

- the agent's token, verbatim;
- `progress` and `total`, as numbers;
- `message`, as upstream text: `[from <server>] ` followed by the upstream's message with control characters escaped as in 8.2 and capped at 512 bytes plus an ellipsis, as for a relayed upstream error. A message that reads as an origin label (the fold above) is dropped, and the numbers go on without it.

The upstream notification's `_meta` is dropped. So is every notification that names another token (another call's, an unknown one, or one that is not a string), whose `progress` does not exceed the last one accepted for the call (the MCP spec requires it to increase), or that arrives after the call has returned. Per call, at most 10 are relayed at once and 5 per second after that; the newest one the limit held back is sent before the call's result, so the agent sees the latest state, and none follows the result. go-sdk dispatches an upstream's notifications in order on one goroutine but reads the call's response on another, so a notification the upstream sent just before its result can be dispatched after it and is then dropped. The mapping lives only as long as the agent's request; nothing about it outlives the call.

**Accepted for M0.** A valid `requestState` can be replayed until it expires; the upstream's own state decides what a repeat means (M3 approvals need a single-use id). The envelope and the attribution of stateful prompts are not bound to an agent session, because stdio has one; both must be once Streamable HTTP serves several.

**Limits of this section.** It covers stdio on both sides. The `Mcp-Method` and `Mcp-Name` header checks ADR 0008 requires apply to Streamable HTTP and land with it. Logging notifications are not relayed (no logging capability, 8.2). A progress notification is written to the agent on the upstream's single notification goroutine, so an agent that stops reading stalls that upstream's incoming notifications and requests (its `elicitation/create` included). Accepted for M0 over stdio, where the result write would stall too; board task T0.28 moves the write off that goroutine before netguard serves Streamable HTTP.
