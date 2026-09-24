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
netguard serve --server <name> --upstream <path> [--upstream-env KEY=VALUE]... [--upstream-env-pass NAME]... [-- <upstream args>...]
```

| Flag | Meaning |
| --- | --- |
| `--server` | Required. The tool prefix: the upstream's profile `server` key (`netdev-ssh-mcp`). Validated against 8.1 before anything is spawned; an invalid name exits 2. |
| `--upstream` | Required. The upstream executable, spawned over stdio. An empty or blank value, or `--`, exits 2. A bare name is looked up on the proxy's `PATH`; MCP hosts that launch with an empty `PATH` need an absolute path. Arguments for it are accepted only after `--` and are passed verbatim, with no shell. A positional argument without a preceding `--` exits 2, reported by position only (`unexpected argument N; arguments for the upstream go after --`), since it may be a password typed as its own argument. An unknown flag, bad flag syntax or a flag without its value is also reported by position (`unknown flag at argument N`, `bad flag syntax at argument N`, `flag at argument N needs a value`); no `serve` error quotes an argument that could be a value. |
| `--upstream-env` | Repeatable `KEY=VALUE` with `KEY` matching `[A-Za-z_][A-Za-z0-9_]*`, for settings that are not secret: the value is on netguard's command line. Errors exit 2 and never quote the argument, which may be a value: an argument without `=` is `--upstream-env argument N is not KEY=VALUE`, a bad key `--upstream-env argument N: key must match [A-Za-z_][A-Za-z0-9_]*`. A `KEY` starting with `NETGUARD_` (ASCII case-insensitive on Windows) exits 2. Nothing from the agent is ever added. |
| `--upstream-env-pass` | Repeatable `NAME` matching `[A-Za-z_][A-Za-z0-9_]*`, for secrets ([ADR 0017](../adr/0017-keep-upstream-secrets-off-the-command-line.md)): netguard copies `NAME` and its value from its own environment (where a client's `env` block puts it) into the upstream's, so the value is never on the command line. Exit 2, before anything is spawned, naming the variable and never the value, when: `NAME` is unset or empty (`--upstream-env-pass NAME: not set in netguard's environment`, `... set but empty ...`); the same name is also given to `--upstream-env` (compared ASCII case-insensitively on Windows, exactly elsewhere); `NAME` starts with `NETGUARD_` (ASCII case-insensitive on Windows); or the argument is not a name (reported by position only, since it may be a value). Accepted residual: a value typed where a name belongs and matching the name pattern is printed by the "not set" error, which must name the variable. A repeated name is passed once. An allow-listed name (`PATH`) is allowed. The value joins the child environment only when the process is built (it is never in `proxy.Command.Env`), and a `proxy.Secret` formats as its marker in every `fmt` verb, JSON and `slog`. It is scrubbed from the upstream's stderr and relayed error messages (below) and from everything netguard writes to stderr; startup logs name the variables (`upstream_env_pass`), never the values. |
| `--policy`, `--inventory`, `--profiles`, `--audit` | Reserved. Refused with exit 2 in M0, because the pipeline they configure is not wired and M0 forwards every call. They are refused wherever they appear, including among the upstream arguments after `--`. |

Upstream environment: the upstream inherits only an allow-list from the proxy. On Unix that is `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR` and the POSIX locale categories `LC_ALL`, `LC_COLLATE`, `LC_CTYPE`, `LC_MESSAGES`, `LC_MONETARY`, `LC_NUMERIC` and `LC_TIME` (no wildcard), matched exactly. On Windows it is `PATH`, `SystemRoot`, `SystemDrive`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PATHEXT` and `COMSPEC`, matched ASCII case-insensitively (no Unicode case folding). Every other variable reaches the upstream only through `--upstream-env` or `--upstream-env-pass`, and `NETGUARD_*` through neither. The child environment is the allow-list, then the `--upstream-env-pass` entries, then the `--upstream-env` entries; since a name may not be given to both flags, the order matters only for overriding an allow-listed variable.

Go API (ADR 0012's list, as amended for ADR 0018): `netguard serve` builds one `proxy.Upstream{Server, NewTransport}`, where `NewTransport` is a `func() mcp.Transport` returning `proxy.Command.Transport()`, a new `exec.Cmd` on every call. `proxy.New` calls it once per connect attempt, so at most twice.

The agent side is stdio; stdout carries only the protocol. The upstream's stderr goes to the proxy's stderr one line at a time, each line prefixed `upstream <server>: ` with control characters escaped as in 8.2. Before anything else (line splitting, the 4096-byte cut, escaping), every `--upstream-env-pass` value of at least 4 bytes is replaced by `[redacted:NAME]` on the raw stderr bytes, including a value split across writes or containing a newline, and the forms the value takes in logs: inside a Go `%q` or `strconv.QuoteToASCII` string, inside a JSON string (with and without HTML escaping, and ASCII-only as Python's `json.dumps` writes it), percent-encoded (query and path escaping), Python byte escapes (`\xNN` for bytes outside printable ASCII as a bytes repr writes them, or for control bytes only as a str repr does), and with backslashes doubled. When forms overlap, the longest wins. A stream that ends in the first 4 or more bytes of a form has that tail replaced too. Once the stream is flushed (the upstream exited or was closed), later stderr bytes are dropped, so a value cannot be completed across the flush. Not scrubbed (accepted residual): values under 4 bytes (too many false matches), base64, HTML entities, a Python repr that escapes a quote character, any other transform, and the part of one passed value that is left over when it overlaps a longer one. The same replacement, plus each form as netguard's escaping renders it, is applied to every line netguard itself writes to stderr (startup errors carrying an upstream message, the `slog` log) and to upstream JSON-RPC error messages relayed to the agent, on the raw message before escaping and the 512-byte cap. Tool results (and progress and elicitation text) are not scrubbed: that is the M2 redactor at the response serialiser (invariant 4). A line longer than 4096 bytes is split at that limit, cut back to a whole UTF-8 character. A final line without a newline is written, prefixed and escaped the same way, when the upstream is closed. Startup (spawn, handshake, `tools/list`) has a 30-second limit, which covers both connect attempts below. The first connect, go-sdk's `server/discover` probe and any `initialize` fallback, is bounded at 5 seconds ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)); no flag or profile field changes that. If the upstream has not connected by then and the 30-second limit has not run out, netguard kills and reaps it (its partial last stderr line is still relayed), logs one line at `warn`, `upstream <server> did not answer server/discover within 5s; restarting it and connecting with initialize only (protocol 2025-11-25)`, starts it again and connects with `initialize` only; `upstream ready` then reports what that negotiated. Any other first-attempt error is not retried, and the second attempt is the last: its error is prefixed `proxy: upstream <server>: connect with initialize only (restarted after server/discover got no answer within 5s): `. The upstream's own start-up side effects run twice when it is restarted. When a connect attempt or `tools/list` fails, the upstream process gets up to 2 seconds to end on its own (none once the 30-second limit has run out); if it ends, the error gains `; upstream process ended: <status>`, with `<status>` as the operating system reports it (`exit status 3`, `signal: terminated`), and if it does not, it is killed and no status is given. If startup fails after the process started, the process is killed (the direct child only); when the upstream answers the handshake with an unsupported protocol version, go-sdk v1.8 first closes the session itself, so the child gets the shutdown grace below (5 seconds, then SIGTERM or kill) before it is reaped. A startup error printed to stderr has control characters escaped as in 8.2, since the upstream's JSON-RPC error message is part of it. On shutdown the upstream's stdin is closed, then it gets 5 seconds before SIGTERM and 5 more before it is killed (on Windows, killed after the first 5). Grandchildren, such as the server behind `uvx` or `npx`, are not signalled. Exit status: 0 when the agent disconnects or on SIGINT or SIGTERM, 1 when the upstream cannot be started or listed or the session fails, 2 for a usage error.

### 8.4 Protocol eras, `_meta` and input requests

Decision records: [ADR 0008](../adr/0008-dual-era-mcp-support.md) (accepted) and [ADR 0014](../adr/0014-stateful-upstream-prompts-to-stateless-agents.md) (accepted). The stateful era is 2025-11-25 and older (initialize handshake, session, server-initiated requests); the stateless era is 2026-07-28 (every request self-describing in `_meta`, MRTR).

**Era detection.** Each side is detected on its own, and the two need not match.

- Upstream, once at connect: go-sdk sends `server/discover` and, if the upstream answers with any error or names no stateless version, falls back to the initialise handshake at 2025-11-25 (and negotiates down to 2024-11-05). If that first connect has not finished within 5 seconds, the probe counts as unanswered ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)): netguard restarts the upstream and connects a new session on the new process with `initialize` only, at 2025-11-25 and negotiating down from there, so that upstream is stateful for the life of the process even if it would have answered the probe later (8.3). The negotiated version is logged with `upstream ready` as `protocol` and `era`.
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
| Stateful | Relayed as `elicitation/create` on the agent's session, attributed to the only call in flight on that upstream; refused when zero or several are in flight, or when another agent session's call on that upstream has ended recently and may still be running there (*Attribution across agent sessions*, below). go-sdk runs incoming upstream requests concurrently, so each call has one prompt slot, shared with netguard's own prompts to a stateful agent (next column): a prompt that arrives while another of the call's prompts is open is refused, and so is any past the 10th in the call. The agent's cancellation of the call cancels the prompt | netguard asks the agent with `elicitation/create`, one request at a time in id order, each taking the call's prompt slot, and retries the upstream with the answers and the upstream's `requestState`, up to 10 rounds and 10 prompts in the call; a round that would pass 10 prompts is refused before anything in it is asked |
| Stateless | Refused (ADR 0014; parking deferred to matrix row 17) | Returned as `input_required` with the relabelled requests and a netguard `requestState`; the agent's retry is verified and the upstream retried once per agent retry, up to 10 rounds and 10 prompts in the call (the count travels in the sealed `requestState`) |

**The agent's answer.** Only an elicitation result crosses back: `accept` with its `content`, or `decline` or `cancel` with nothing. Its `_meta` is dropped. A stateful agent's `accept` content is checked against the relabelled schema by go-sdk; a stateless agent's is left to the upstream.

**`requestState` toward a stateless agent.** netguard never hands out the upstream's `requestState`, in the clear or otherwise readable. It issues `ng2.<base64url(nonce || ciphertext)>`, sealed with AES-256-GCM under a random per-process key and a random 96-bit nonce, with the prefix as additional authenticated data. The ciphertext holds JSON with the upstream server, the unprefixed tool, a SHA-256 digest of the call's arguments (as sent, insignificant whitespace removed, so key order and duplicate keys count), the outstanding input request ids, the upstream's own `requestState`, the round, the prompts put to the human so far and an expiry 30 minutes out. The sealed length reveals roughly how large the upstream's state is; its content stays hidden. The upstream's state must be at most 64 KiB, and the sealed string at most 96 KiB: the proxy measures the sealed string before issuing it and refuses the prompt (tool error) rather than issue a state it would not accept back, and it refuses any incoming `requestState` longer than the same 96 KiB. On the retry netguard authenticates and decrypts it, checks the expiry, server, tool and argument digest, drops answers to ids that are not outstanding, checks every remaining answer against the allow-list above, and only then sends the upstream its own `requestState` and the cleaned answers. `inputResponses` that arrive without a `requestState` are ignored and the call goes up as a first call (8.2). A restart invalidates every outstanding `requestState`; the agent calls again without one.

**Progress.** When the agent's `tools/call` carries a `progressToken` that is a string, or an integer of magnitude at most 2^53-1 (JavaScript's `Number.MAX_SAFE_INTEGER`; a larger one may have been rounded on the way in, and anything else is ignored), netguard gives the upstream call a token of its own: 128 random bits as 26 base32 characters, new for every agent request (so for every MRTR retry too) and kept across the rounds netguard runs within one. The agent's token never goes upstream. Without one, the upstream is sent no token. While the call is open, an upstream `notifications/progress` naming netguard's token becomes netguard's own notification to the agent, built from:

- the agent's token, verbatim;
- `progress` and `total`, as numbers;
- `message`, as upstream text: `[from <server>] ` followed by the upstream's message with control characters escaped as in 8.2 and capped at 512 bytes plus an ellipsis, as for a relayed upstream error. A message that reads as an origin label (the fold above) is dropped, and the numbers go on without it.

The upstream notification's `_meta` is dropped. So is every notification that names another token (another call's, an unknown one, or one that is not a string), whose `progress` does not exceed the last one accepted for the call (the MCP spec requires it to increase), or that arrives after the call has returned. Per call, at most 10 are relayed at once and 5 per second after that. The newest one the limit held back is sent as soon as the rate allows another (about 200 ms after the bucket empties), or before the call's result if the call ends first, so the agent sees the latest state; none follows the result. go-sdk dispatches an upstream's notifications in order on one goroutine but reads the call's response on another, so a notification the upstream sent just before its result can be dispatched after it and is then dropped. The mapping lives only as long as the agent's request; nothing about it outlives the call, except as below.

*Delivery (T0.28).* Nothing is written to the agent on the goroutine that dispatches the upstream's notifications, because go-sdk hands an upstream's notifications and requests (its `elicitation/create` included) to netguard one at a time, and a write that waits on a slow agent would hold up every later one. The relay only updates the call's state and queues the rebuilt notification. Each call with progress has a queue of at most 10 notifications and one sender goroutine that writes them to the agent in order; when the queue is full, the newest entry is replaced, so progress still increases and a slow agent costs a bounded amount of memory per call. When the call ends, it first leaves the upstream's in-flight set (which matters for attributing a stateful upstream's prompt, so another agent's call is never refused because of a call that has already returned), and then netguard waits at most 1 second for the sender to write the queue, with the held-back notification added, before it returns the result. If the agent has not read it all by then, the rest of the queue is dropped and no new write starts. A write already in progress holds the agent transport's write lock, so the result still follows it. A sender that has taken a notification but is still waiting for the lock when netguard gives up can write it after the result: on stdio that is accepted (at most one notification for a finished call, which the agent may ignore); over Streamable HTTP go-sdk refuses it, because writing the result closes the call's stream (8.5). go-sdk's stdio transport cannot abandon a write in progress, so a sender stuck on an agent that has stopped reading ends when the agent reads again or its connection closes, at most one per call. Over Streamable HTTP each write has a deadline (8.5), so it ends within that.

*Attribution across agent sessions (H1 in the review of PR #68, widened by J1 in its re-review).* A stateful upstream's `elicitation/create` names no call. A call can end on netguard's side while the upstream is still working on it, in two ways. It can be cancelled: the agent cancels it, a 2026-era POST is dropped (which cancels the call), a write deadline drops the connection of a stateless call, the session is deleted or expires, or netguard closes; netguard then sends `notifications/cancelled`, which the upstream may ignore. Or the upstream can answer it and keep working anyway: a background job it started, or a prompt it sent just before its result that go-sdk dispatches after it. Either way the prompt arrives when another agent session's call is the only one in flight. So **every** call that ends is remembered as an *orphan* of its agent session, for `OrphanTTL` (5 minutes by default; 8.5), not only a cancelled one.

A prompt is relayed only when every call that could have sent it belongs to one agent session: exactly one call in flight on the upstream, and every live orphan on it left by that call's session. Otherwise it is refused: the upstream gets a JSON-RPC error, and the refusal (`it cannot be attributed to one call: another agent session's call on this upstream has ended recently and the upstream may still be working on it`, naming no session, principal or prompt text) is appended to the result of every call in flight on that upstream, as for any unattributed prompt. One exception keeps the more useful answer: when exactly one call is in flight but an orphan refuses it, and that call's agent could not have been shown any prompt anyway (a stateless agent, ADR 0014, or one that did not declare form elicitation), the refusal says *that* instead. It is still a refusal of a prompt netguard did not attribute to that call, so it is recorded as a note on that call alone (it names that call's tool, so it goes to no other): appended to a result the upstream completes, never put in place of the upstream's error (T0.42). No prompt crosses to a human in either case. A refusal stands in for an upstream error only when the prompt was attributed to the call that failed (exactly one call in flight and no foreign orphan) and netguard then declined it.

Orphans are keyed by netguard's own key for the agent session, never by the session itself, so a record never keeps a closed session alive. The key comes from what the session is, not from whether the proxy has a listener (T0.43). The session `Proxy.Run` serves (stdio) is recorded when Run connects it and has a key of its own (a request go-sdk dispatches before the record exists waits for it, and gets the shared entry only if its context ends first), so its own orphan never blocks a prompt that could otherwise be relayed to it, with or without an HTTP listener on the same proxy; `netguard serve` runs one such session (ADR 0012), and a second Run on one proxy (tests only) gets a second key. A stateful session over the listener is keyed by its session id. Anything else (a request over the listener with no session id, which comes from a per-request session of the stateless era and can never own another call, or a call with no session) goes to one shared entry that is foreign to every later call, that key's own included. An upstream remembers at most 1024 keyed sessions; past that the shared entry, expiring with the newest, stands for all the others and blocks every session. Expired keyed orphans are forgotten whenever a call ends and before a prompt is attributed, and each one is logged at Info naming the principal it was blocking for. The shared entry is not: it is never pruned (it simply stops blocking when its time passes), never logged, and names no principal, so a refusal it causes cannot be traced from the log (T0.44 open). A stateless agent's ended calls therefore block prompts to every other call on that upstream, each for `OrphanTTL`, renewed by each new call; that costs the stateless agent nothing it could have received (ADR 0014) but does refuse prompts to other agents, for as long as it keeps calling.

**Accepted for M0.** A valid `requestState` can be replayed until it expires; the upstream's own state decides what a repeat means (M3 approvals need a single-use id). The envelope is not bound to an agent session (T0.30 binds it to the principal). A prompt that arrives for an orphan while the same session has one call in flight is relayed to that call, and so to the same session's human, who may answer the earlier call's prompt; across sessions it is refused (above). With more than one agent session on one upstream, a stateful upstream's prompt is refused for up to `OrphanTTL` after any other session's call ends, whether or not that call was cancelled: netguard cannot tell whose prompt it is, and refusing is the safe answer. That bound is per ended call, not a steady state: through the shared entry, one principal can keep every other principal's stateful prompts on an upstream refused with one stateless request per `OrphanTTL` (or by ending calls on more than 1024 stateful sessions), and the log does not show which principal it was. That part is **not** accepted: it is open, T0.44, and must land before `--listen` (T0.31). It fails closed (no prompt reaches the wrong human, nothing leaks). A refusal note tells the agent that an upstream prompt existed on that upstream around the time of its call (existence and timing), never its text or whose it may have been; and which refusal an agent sees (the orphan reason, or for a stateless agent whether the ADR 0014 wording arrives as a note or as netguard's own error) reveals whether another agent session ended a call on that upstream within `OrphanTTL`, the same disclosure the orphan refusal's own text makes.

**Limits of this section.** It covers both agent transports (the HTTP listener's own rules are in 8.5) and stdio upstreams. Logging notifications are not relayed (no logging capability, 8.2). An agent that stops reading no longer stalls an upstream's incoming notifications and requests (T0.28, *Delivery* above). It stalls only its own calls, and each of their ends is delayed by at most the 1-second final wait.

A relayed `elicitation/create` from a stateful upstream is sent to the agent under the context of the agent's call it is attributed to, and is cancelled by either side: the agent cancelling the call or the upstream cancelling its request. Over Streamable HTTP that context is what puts the prompt on the POST stream of that call.

### 8.5 HTTP listener

Decision record: [ADR 0016](../adr/0016-streamable-http-listener.md) (accepted). This section describes `(*Proxy).HTTPHandler` in `internal/proxy` (T0.27). The `netguard serve --listen` flags, the token file and the lifecycle are T0.31, and T0.33 completes this section. Until then the agent side of `netguard serve` is stdio only (8.3).

**Endpoint.** One handler serves `/mcp` for both eras. Any other path gets 404. Requests pass these checks in order, and the first failure answers:

| # | Check | Answer |
| --- | --- | --- |
| 1 | Connection cap: at most 128 open TCP connections (a limiting listener in `cmd/netguard`, wired by `--listen` in T0.31) | Further connections wait in the kernel backlog |
| 2 | Host: a request that arrived on a loopback address must name a loopback host (`localhost`, `127.0.0.0/8`, `::1`). netguard checks this itself before authentication, and go-sdk's own check stays on behind it | 403 |
| 3 | Origin: any `Origin` header (including `null` and an empty one), or `Sec-Fetch-Site` other than `none` or `same-origin`, on every method, before authentication | 403. No CORS header is ever sent |
| 4 | Path | 404 |
| 5 | Bearer token (`Authorization: Bearer <token>`), through go-sdk's `auth.RequireBearerToken` | 401 with `WWW-Authenticate: Bearer` |
| 6 | POSTs in flight: 64 overall and 32 per principal, long-lived `subscriptions/listen` streams included | 503 with `Retry-After: 1` |
| 7 | Era dispatch on `MCP-Protocol-Version` | none (routing) |
| 8 | Stateful sessions: at most 16 open, and at most 4 per principal. A session-less POST to the stateful handler (which may open a session) past either | 503 with `Retry-After: 1` |
| 9 | go-sdk: body at most 4 MiB, `Content-Type`, `Accept`, `_meta` and `MCP-Protocol-Version` agreement, `Mcp-Method` and `Mcp-Name` against the body | 413, 415, 400 or 404 as go-sdk maps them |

`OPTIONS` without `Origin` reaches go-sdk and gets 405. Every 401, 403, 404, 413 and 503 carries `Connection: close` and the server closes the connection after it, so a refused client, authenticated or not, holds none of the 128 connection slots.

**Tokens and principals.** Every configured token is named: its principal name is 1 to 64 characters from `[A-Za-z0-9_.:-]`, and there are no unnamed tokens. A token is at least 32 bytes of printable ASCII with no spaces, and no two principals share one. Tokens must be random, for example the output of `openssl rand -hex 32` (256 bits); netguard checks their shape, not their entropy, so a guessable token is the operator's to avoid. The handler keeps only SHA-256 digests. It compares the digest of a presented token with every configured digest in constant time and does not stop at a match. Failed authentications are logged at warn with the remote address and a reason (`no Authorization header`, `not a bearer token`, `unknown token`), at most once per second. The header and the token are never logged or echoed. The principal is attribution only: it is carried on the call for the M4 audit line and, from T0.30, bound into `requestState`. It is never an approver identity (invariant 6), and nothing else that arrives over the listener is one either.

**Eras.** A request whose `MCP-Protocol-Version` is at or after `2026-07-28` (compared as a string) goes to a stateless go-sdk handler, which ignores `Mcp-Session-Id` and cancels the upstream call when the POST closes. Every other request goes to a stateful handler: `initialize`, requests with a session id, 2025-era requests with or without the header, and malformed ones, which get go-sdk's own error. Both serve the one `mcp.Server`, so a 2026 MRTR retry reaches the proxy that sealed its `requestState`. Neither handler sets `JSONResponse`, so responses are SSE and a call's progress travels on its own POST stream. Neither has an event store (no resumption). A stateful session belongs to the principal that opened it: a request on it with another principal's token gets 403 from go-sdk, and that principal's DELETE cancels nothing. A stateful session with no POST in progress for 30 minutes (`SessionTimeout`; an open GET stream does not count) is closed by netguard, which first cancels any call still running on it (*Slow agents*). netguard registers every session a session-less POST leaves behind: go-sdk names the new session in the response of any such POST and closes it again at the end of the request unless it was an `initialize`, so whatever the response names and go-sdk kept is registered, without netguard asking whether it initialised. go-sdk's own idle timer is the longer of the two, so a session netguard did not register would be invisible to the idle accounting that cancels a call stuck upstream. Registration happens only after go-sdk has sent that response, so an agent can POST on the new session before it is registered; such a POST, on its principal's behalf, is counted and becomes a POST in progress on the session when it is registered, so the idle clock never runs under it (T0.45; before, a call made in that POST could be cancelled at `SessionTimeout` while it ran). Session ids are logged only as the first 12 hex digits of their SHA-256.

**Orphan TTL.** A call that has ended keeps a stateful upstream's prompt from being attributed to another agent session for `OrphanTTL`, because the upstream may still be working on it (8.4, *Attribution across agent sessions*). It is its own option, separate from `SessionTimeout` and much shorter: **5 minutes** by default, against 30 for the idle timeout. An idle session costs one of 16 slots; an orphan refuses other agents' prompts, so it must expire soon after the upstream could still be working on the call. The default is an orchestrator recommendation from the re-review of PR #72 (T0.40) and is deliberately easy to revisit: change `defaultOrphanTTL` and this paragraph. Reaping a keyed orphan (a stateful session's, or the local agent's) is logged at Info with the server and the principal it was blocking for. The shared entry that stands for every stateless per-request session and every session past 1024 is not reaped, logged or attributed to a principal (8.4; T0.44 open), and `OrphanTTL` bounds each ended call, not how long a busy agent keeps other sessions' prompts refused.

**Tool calls.** Calls in flight are capped at 8 per agent session and 32 per principal. They are counted as calls, not requests, because a 2025-era call whose POST was dropped keeps running. A call over either cap is refused before anything reaches the upstream, with a tool result `isError: true` and text `netguard refused <server>.<tool>: <n> calls are already in flight on this session (limit 8); retry when one finishes`, or `... for principal <name> (limit 32) ...`. go-sdk's session close waits for the calls in flight instead of cancelling them. So a DELETE from the session's own principal first cancels that session's calls, and `Proxy.Close` cancels every call, refuses new ones and closes every agent session before it closes the upstreams.

**Slow agents.** Every write and flush to the agent runs under a 10-second write deadline, cleared after the write so an idle stream has none. A write that cannot finish in time fails, net/http drops the connection and cancels the request, and the call's progress sender exits. A stateless call is then cancelled. A stateful call keeps running without its POST (go-sdk detaches it), within the call caps, until it ends, the agent cancels it, its session is deleted, or the session has had no POST in progress for `SessionTimeout` (30 minutes). go-sdk's own idle close waits for such a call instead of cancelling it, so a call stuck upstream would hold its session and its slot for good; netguard therefore runs its own idle expiry on the same clock (paused while a POST for the session is in progress, reset when the last one ends), which cancels the session's calls and then closes the session. One principal holds at most 4 of the 16 session slots, so it cannot pin them all. The write deadline is also cleared when each request starts, so none is inherited across a keep-alive connection. A request body must arrive within 30 seconds: the read deadline is set only when the request has a body, and is cleared as soon as the body has been read, before net/http's background read. The `http.Server` that `cmd/netguard` builds sets `MaxHeaderBytes` 64 KiB, `ReadHeaderTimeout` 10 seconds and `IdleTimeout` 120 seconds, and no server-wide `ReadTimeout` or `WriteTimeout`, either of which would cut long SSE responses. It registers `Proxy.Close` to run on shutdown (`srv.RegisterOnShutdown`): `Shutdown` waits for connections to go idle and a 2025-era session's GET stream never does, while `Close` ends it by closing the session.

**Environment.** `HTTPHandler` fails if `MCPGODEBUG` is set, even to an empty value. `cmd/netguard` runs the same check first so it can exit 2 with the variable named (T0.31). Both return the one error value `proxy.ErrMCPGODEBUG`, so there is one refusal text in one place.

**API.** ADR 0016 names one export, `(*Proxy).HTTPHandler(HTTPOptions) (http.Handler, error)`; its surface is that method, its parameter type `HTTPOptions`, the constant `HTTPPath` (`/mcp`) and the error value `ErrMCPGODEBUG`, and nothing else in `internal/proxy` is exported for the listener. `HTTPOptions` carries the tokens by principal name and the caps and timeouts above (`MaxInFlight`, `MaxInFlightPerPrincipal`, `MaxSessions`, `MaxSessionsPerPrincipal`, `MaxCallsPerSession`, `MaxCallsPerPrincipal`, `SessionTimeout`, `OrphanTTL`, `WriteTimeout`, `BodyReadTimeout`). Each zero value means the default, a negative value is an error naming the field, and no field turns a check off. The handler can be built once per proxy. The listener, its connection cap, the `http.Server` settings, the shutdown hook and the `MCPGODEBUG` check for exit 2 live in `cmd/netguard` (`listen.go`), unexported, as ADR 0016 assigns them.
