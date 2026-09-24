# Network-Device MCP Servers: Tool-Surface Catalog

Compiled 2026-09-22/23 for the design of a guardrail proxy that sits in front of network MCP servers and normalizes/polices their tool calls.

Method: GitHub README pages via fetch, raw source files pulled from `raw.githubusercontent.com` (tool signatures below are taken from source where marked **[src]**; otherwise from README/registry pages and marked **[doc]**). GitHub API and commit pages were blocked in this environment, so "last activity" is inferred from release pages / PyPI upload dates and marked *(uncertain)* where so. Star counts are as shown on the repo page at fetch time.

Scope: the servers explicitly requested, plus everything actionable mined from the hecisaza curated list (https://github.com/hecisaza/network-mcp-servers).

---

## Part 1 — Per-server catalog

### 1.1 krisiasty/netdev-ssh-mcp (multi-vendor SSH, Go)

| Field | Value |
|---|---|
| Repo | https://github.com/krisiasty/netdev-ssh-mcp |
| Language / framework | Go 1.26+, official `github.com/modelcontextprotocol/go-sdk/mcp` **[src: main.go]** |
| Transport | stdio only (`mcp.StdioTransport`) **[src]** |
| Platforms | Arista EOS, Cisco NX-OS, Cisco IOS/IOS-XE, Juniper Junos, FortiGate FortiOS |
| Device targeting | Per-call `host` (hostname/IP) + optional `device_type` enum (`eos`,`ios`,`nxos`,`junos`,`fortios`) + optional `username`/`port`. No inventory file. Password comes from `DEVICE_PASSWORD` env or SSH agent (`SSH_AUTH_SOCK`); never passed via tool params. |
| Install | `brew install --cask krisiasty/tap/netdev-ssh-mcp` or build from source (Go). Single static binary — trivially containerizable. |
| Stars / license | 3 stars, Apache-2.0 |
| Last activity | Releases up to v1.6.6; the releases page shows relative dates and the extractor reported "Sept 16" — year *(uncertain, likely 2026 given Go 1.26 requirement)* |

Tools **[src: main.go, internal/netdev/show.go, config.go]**:

| Tool | Params (JSON schema) | Class |
|---|---|---|
| `get_config` | `host: string` (req), `username?: string`, `port: int` (default 22), `config_type: string` (`running`\|`startup`), `device_type?: string` | READ_CONFIG |
| `run_show_command` | `host: string` (req), `command: string` (req), `username?`, `port`, `device_type?` | READ_OPERATIONAL (server-enforced) |
| `run_ping` | `host`, `destination` (req), `username?`, `port`, `count?: int`, `timeout?: int`, `source?: string`, `vrf?: string`, `size?: int`, `outgoing_interface?: string`, `device_type?` | READ_OPERATIONAL |
| `run_traceroute` | `host`, `destination` (req), `username?`, `port`, `max_hops?: int`, `timeout?: int`, `probe?: int`, `source?`, `vrf?`, `outgoing_interface?`, `device_type?` | READ_OPERATIONAL |
| `trust_host_key` | `host` (req), `port`, `confirm: bool`, `replace_existing: bool` | LOCAL_ADMIN (writes known_hosts on the proxy/host side, not the device) |

Safety features (strongest of the SSH servers surveyed):
- Strictly read-only by design; no config-write tool exists.
- `run_show_command` enforces command prefix: must start with `show` (EOS/IOS/NX-OS/Junos) or `get` (FortiOS); `show running-config`/`startup-config`/`show configuration` are rejected and redirected to `get_config`; FortiOS `show`/`config`/`execute`/`diagnose` blocked except ping/traceroute via the dedicated tools.
- Secret obfuscation: passwords, SNMP communities, BGP/OSPF/TACACS/RADIUS/IKE keys replaced with deterministic SHA-256 hashes in `get_config` and `run_show_command` output; `--no-obfuscate` disables.
- SSH host-key verification against `known_hosts` on by default; `--insecure-skip-host-key-check` / `SKIP_HOST_KEY_CHECK=true` to disable; `trust_host_key` two-step confirm flow.

Proxy notes: because target is a free-form `host` per call (no inventory), a proxy must supply its own allow-list of hosts. Credentials are ambient (env), so the proxy cannot see or scope them per call.

#### Update 2026-09-23: the obfuscation is an unkeyed hash with gaps (T0.29)

Read at tag `v1.6.6`, commit `be3e36342b0c71007ce416a435dfdfecc966ea13` **[src: [`internal/netdev/obfuscate.go`](https://github.com/krisiasty/netdev-ssh-mcp/blob/be3e36342b0c71007ce416a435dfdfecc966ea13/internal/netdev/obfuscate.go), [`show.go`](https://github.com/krisiasty/netdev-ssh-mcp/blob/be3e36342b0c71007ce416a435dfdfecc966ea13/internal/netdev/show.go), [`config.go`](https://github.com/krisiasty/netdev-ssh-mcp/blob/be3e36342b0c71007ce416a435dfdfecc966ea13/internal/netdev/config.go), [`main.go`](https://github.com/krisiasty/netdev-ssh-mcp/blob/be3e36342b0c71007ce416a435dfdfecc966ea13/main.go)]**. This corrects the "Secret obfuscation" bullet above.

- **Mechanism [src].** `obfuscateConfig` splits output into lines and tries 28 line-anchored regexes (EOS, IOS/IOS-XE, NX-OS, Junos, FortiOS) in order. The first match wins, and its secret group becomes `[h:` + hex of the first 6 bytes of `sha256(value)` + `]`. It runs on `get_config` and `run_show_command` output only. `run_ping`, `run_traceroute` and error strings are not obfuscated. The package-level `Obfuscate` flag defaults to true, and `--no-obfuscate` turns it off.
- **Unkeyed [src].** `hashSecret` is plain SHA-256 with no key or salt, so anyone holding the output can hash a word list and match it. For example `public` gives `[h:efa1f375d761]` and `private` gives `[h:715dc8493c36]` (reproduced with `printf public | shasum -a 256`). SNMP communities, type-7 strings and lab passwords are exactly the short values this recovers. It does not meet NetGuard invariant 4 (keyed HMAC tokens), so NetGuard must not count it as redaction.
- **Wrong token captured [src, run].** We ran the upstream function unchanged against NetGuard's redaction fixtures (`tests/fixtures/configs/`). Several patterns hash a keyword and leave the secret in clear next to it. The output looks obfuscated, which makes this worse than no match at all:

  | Line shape | What upstream hashes | Secret left in clear |
  |---|---|---|
  | `username X ... secret sha512 <crypt>` (the default EOS hash format) | `sha512` | the `$6$` hash |
  | `ntp authentication-key N md5 7 <key>` | `7` | the key |
  | `ip ospf message-digest-key N md5 7 <key>` | `7` | the key |
  | `key-string 7 <key>` (key chain) | `7` | the key |
  | Junos `pre-shared-key ascii-text "<key>"` (the IOS IKEv2 regex shadows the Junos one) | `ascii-text` | the `$9$` key |

- **Not matched at all [src, run].** `snmp-server host <ip> [traps] version 2c <community>` (EOS, IOS-XE, NX-OS); NX-OS `radius-server host <ip> key 7 "<key>"`; NX-OS `snmp-server user ... priv <key>`; Junos `secret "$9$..."` under tacplus/radius; Junos `authentication-key 1 type md5 value "..."` (NTP); Junos `set`-format lines (the regexes expect the hierarchical form).
- **Covered [src].** `enable secret|password`, `username ... secret|password <type-digit>`, `snmp-server community`, `Community:` lines in `show snmp community`, BGP `neighbor X password`, `tacacs-server`/`radius-server key`, IOS-XE `key` inside `tacacs server` blocks, `crypto isakmp key`, IOS IKEv2 `pre-shared-key`, bare `password` (line vty), OSPF `authentication-key`, IS-IS keys, Junos `encrypted-password`/`authentication-key "..."`/SNMPv3 passwords/`community`, and FortiOS `ENC` and quoted secrets.
- **Totals per fixture (secrets left in clear / total):** `eos` 5/13, `ios-xe` 3/22, `nxos` 5/13, `junos` 7/13, `eos-4.16` 0/4, `fortios` 0/6. NetGuard's own rules (`internal/redact/rules.go`) cover all of them, with a type-digit-tolerant grammar (`(?:\d\s+)?` before the value) and the `unix-crypt-hash`, `cisco-snmp-host`, `junos-secret-data` and `junos-9-hash` rules.
- **Tests [src].** At this tag the repo has no unit test for `obfuscateConfig` or `hashSecret`. Only `device_type_test.go` and `handlers_test.go` exist.
- **Consequence for NetGuard.** Keep upstream obfuscation on in M0 as defence in depth, because NetGuard does not redact until M2 (`docs/install.md`). Do not treat it as a security control. When NetGuard redaction ships (matrix row 15), it runs on every result anyway and must not skip a line because it already holds an `[h:...]` token. An upstream issue suggesting a keyed HMAC is drafted, not filed, in [`draft-netdev-ssh-mcp-keyed-hash-issue.md`](draft-netdev-ssh-mcp-keyed-hash-issue.md).

---

### 1.2 carlmontanari/scrapli-mcp (Scrapli, Python)

| Field | Value |
|---|---|
| Repo | https://github.com/carlmontanari/scrapli-mcp (author's note: it is ~100 LOC, read the source) |
| Framework | `mcp.server.fastmcp.FastMCP` (official Python SDK's FastMCP) **[src: main.py]** |
| Transport | stdio (`mcp.run()` default) **[src]** |
| Device targeting | Hard-coded `HOSTS` dict in `main.py` keyed by alias; each entry carries `host`, `auth_username`, `auth_password`, `auth_strict_key: False`, `platform` (e.g. `cisco_iosxe`), `transport: asyncssh`. Exposed as MCP resources `hosts://` and `hosts://{host}` (which returns the dict **including the password**). |
| Install | `pip install -r requirements.txt`, run `python main.py` |
| Stars / license | 6 stars, 1 commit, LICENSE file present (type not confirmed) *(uncertain)* |
| Last activity | Single commit; effectively a demo. Date *(uncertain)* |

Tools **[src]**:

| Tool | Params | Class |
|---|---|---|
| `execute_ssh_command` | `host: str` (alias in HOSTS), `command: str` → `tuple[bool, str]` | EXEC_ARBITRARY (uses `send_command`, i.e. privileged-exec, no filtering; `configure terminal` would not enter config mode via `send_command` but any exec-mode command such as `reload` or `write erase` passes) |

Also registers a prompt named `execute_ssh_command` (name collision with the tool in Python; harmless but sloppy).

Safety: none. Strict host key checking disabled. Resource leaks credentials.

Alternate Scrapli server: `mmaeso/mcp-server-scrapli` (https://github.com/mmaeso/mcp-server-scrapli) — returned 404 at fetch time and is flagged as broken in TensorBlock's awesome list issue #2317; treat as dead.

---

### 1.3 Netmiko servers

Several exist; the two most substantive are `upa/mcp-netmiko-server` (most stars, safety flags) and `ntunes/netmiko-mcp-server` (most complete inventory/parallel model, HTTP transport). `melihteke/mcp-server-netmiko` (the one in hecisaza's list, https://github.com/melihteke/mcp-server-netmiko) has 0 stars, 3 commits, no README content — not catalogued further. `Michaelbecze/Netmiko-MCP` (https://github.com/Michaelbecze/Netmiko-MCP) is a two-file demo, 0 stars.

#### 1.3a upa/mcp-netmiko-server

| Field | Value |
|---|---|
| Repo | https://github.com/upa/mcp-netmiko-server |
| Framework | `mcp.server.fastmcp.FastMCP` **[src: main.py]**, single file |
| Transport | stdio default; `--sse` starts Starlette/uvicorn SSE on `--bind`/`--port` (default 127.0.0.1:10000) **[src]** |
| Device targeting | TOML inventory path as positional CLI arg; `[default]` table for shared `device_type`/`username`/`password`/`port`; one table per device with `hostname` + `device_type` (validated against netmiko `platforms + telnet_platforms`). Tools take the device **name**. |
| Install | `git clone` + `uv run`; no PyPI package; no Dockerfile seen *(uncertain)* |
| Stars / license | 35 stars, 9 forks; license not shown *(uncertain)* |
| Last activity | No releases; commit date *(uncertain)* |

Tools **[src]**:

| Tool | Params | Class |
|---|---|---|
| `get_network_device_list` | none → JSON `[{name, hostname, device_type}]` | INVENTORY_READ |
| `send_command_and_get_output` | `name: str`, `command: str` → str | EXEC_ARBITRARY (exec-mode; filtered only in `--secured` mode) |
| `set_config_commands_and_commit_or_save` | `name: str`, `commands: list[str]` → str (calls `send_config_set`, then `commit()` if present, then `save_config()`) | WRITE_CONFIG (auto-commit + auto-save, no dry-run) |

Safety **[src]**:
- `--disable-config` flag makes the config tool return a refusal string.
- `--secured` flag: `send_command_and_get_output` rejects commands whose text *starts with* any of `r`, `clear`, `copy`, `file`, `write`, `delete`, `shut`, `start`, `power`, `debug`, `lock`, `set`. Note the single-letter `r` prefix (meant for request/reload/restart) also blocks `route`, `run`, etc.; and `show` is not an allow-list — anything not starting with those prefixes (e.g. `configure`, `terminal`, `ping`) passes.
- Connect timeout 3 s, read timeout 20 s.
- No secret redaction, no audit log.

#### 1.3b ntunes/netmiko-mcp-server

| Field | Value |
|---|---|
| Repo | https://github.com/ntunes/netmiko-mcp-server |
| Framework | `fastmcp.FastMCP` (jlowin FastMCP 2.x), tools registered via `register_*_tools(mcp, pool, config)` in `src/netmiko_mcp/tools/{commands,config_tools,discovery}.py` **[src]** |
| Transport | stdio default; `--transport streamable-http --port 8339` **[doc README]**; Docker + docker-compose provided |
| Device targeting | YAML inventory `config/devices.yaml` (path via `NETMIKO_MCP_CONFIG`), devices have `host`, `device_type`, `credential_profile`, `tags`, groups; credentials from env vars. Tools take device **name** or `@group` references. Connection pooling with health checks. |
| Install | `pip install -e .` or Docker |
| Stars / license | 4 stars, MIT |
| Last activity | *(uncertain)* |

Tools **[src]** (all take FastMCP `ctx: Context` first; omitted below):

| Tool | Params | Class |
|---|---|---|
| `send_command` | `device: str`, `command: str`, `use_textfsm: bool=False`, `read_timeout: float=30.0` | EXEC_ARBITRARY (no filtering) |
| `send_command_parallel` | `devices: list[str]` (names or `@group`), `command: str`, `max_concurrent: int=10`, `use_textfsm: bool=False` | EXEC_ARBITRARY (fleet-wide) |
| `send_commands_sequence` | `device: str`, `commands: list[str]`, `stop_on_error: bool=False` | EXEC_ARBITRARY |
| `send_config` | `device: str`, `config_commands: list[str]`, `save_config: bool=False`, `dry_run: bool=False`, `enter_config_mode: bool=True` | WRITE_CONFIG |
| `send_config_parallel` | `devices: list[str]`, `config_commands: list[str]`, `save_config: bool=False`, `max_concurrent: int=5`, `rollback_on_error: bool=False` | WRITE_CONFIG (fleet-wide) |
| `list_devices` | `tag?: str`, `device_type?: str` | INVENTORY_READ |
| `get_device_info` | `device: str`, `include_connection_status: bool=False` | INVENTORY_READ |
| `list_groups`, `get_device_types`, `get_tags`, `get_pool_status` | none | INVENTORY_READ |
| `test_connection` | `device: str` | READ_OPERATIONAL |

Safety: `dry_run` and `rollback_on_error` flags on config tools (best-effort; dry-run depends on platform); no command filtering, no read-only mode, no redaction. Streamable-HTTP has no auth mentioned.

---

### 1.4 mcp-telecom (Avinash-Amudala/MCP-Telecom)

| Field | Value |
|---|---|
| Repo / PyPI | https://github.com/Avinash-Amudala/MCP-Telecom · https://pypi.org/project/mcp-telecom/ (v0.2.0 uploaded 2026-04-07 per PyPI JSON) |
| Framework | `mcp.server.fastmcp.FastMCP`, tools in `src/mcp_telecom/server.py`; validation in `safety.py`; JSONL audit in `audit.py` **[src]** |
| Transport | stdio (README); Dockerfile + docker-compose present |
| Vendors | Nokia SR OS, Cisco IOS/IOS-XE/IOS-XR/NX-OS, Juniper Junos, Arista EOS; via Netmiko SSH, plus optional NETCONF, gNMI, SNMP |
| Device targeting | `devices.yaml` inventory (name, type, IP, creds); tools take `device: str` name; multi-device tools take `devices: str` (comma-separated, empty = all) |
| Install | `pip install mcp-telecom` / `mcp-telecom[all]` |
| Stars / license | 1 star, MIT |

Tools (~60) **[src]** — representative signatures:

| Group | Tools (params) | Class |
|---|---|---|
| Canned show | `show_bgp_summary(device)`, `show_bgp_neighbors(device)`, `show_routing_table(device)`, `show_ospf_neighbors(device)`, `show_mpls_lsp(device)`, `show_interfaces(device)`, `show_interface_detail(device, interface)`, `show_lldp_neighbors`, `show_lag_status`, `show_arp_table`, `show_mac_table`, `show_system_info`, `show_alarms`, `show_ntp_status`, `show_cpu`, `show_memory`, `show_environment`, `show_log_events`, `show_nokia_services` (all `device: str`) | READ_OPERATIONAL (vendor-mapped canned commands) |
| Config read | `backup_config(device)`, `compare_configs(device, backup_file)`, `netconf_get_config(device, source="running")`, `compliance_check(device)`, `compliance_check_rule(device, rule_name)` | READ_CONFIG |
| Free-form | `run_command(device, command)`, `parallel_command(command, devices="", max_workers=10)` | READ_OPERATIONAL (allow-list enforced) |
| Named ops | `run_vendor_operation(device, operation)`, `parallel_operation(operation, devices="")`, `compare_devices(operation, devices="")` | READ_OPERATIONAL |
| Inventory/health | `list_devices()`, `list_device_capabilities(device)`, `health_check(device=None)`, `parallel_health_check(devices="")`, `pool_stats()`, `get_audit_log(count=25)` | INVENTORY_READ |
| NETCONF/gNMI/SNMP | `netconf_get_operational(device, operation)`, `netconf_capabilities(device)`, `telemetry_subscribe(device, paths=..., interval_ms=10000)`, `telemetry_query`, `telemetry_history(device, path, count=20)`, `telemetry_unsubscribe(device)`, `snmp_get(device, oids=..., community="public")`, `snmp_walk(device, base_oid=..., community="public")`, `snmp_device_overview(device, community)` | READ_OPERATIONAL (subscribe creates server-side state, not device state) |
| Topology | `discover_topology(devices="")`, `show_topology()`, `show_topology_json()`, `show_topology_mermaid()`, `find_path(source, target)`, `show_device_neighbors(device)` | READ_OPERATIONAL |
| Lab/misc | `clab_generate(scenario)`, `clab_devices_yaml(scenario)`, `clab_scenarios()`, `start_dashboard(port)`, `start_metrics_endpoint(port)` | LOCAL_ADMIN |

Safety **[src: safety.py]**: `is_safe_command` requires the lowercase command to start with one of `show`, `display`, `monitor`, `ping`, `traceroute`, `tracepath` **and** not match a regex blocklist (`configure`, `config t`, `edit`, `set`, `delete`, `rollback`, `commit`, `write mem|erase`, `copy running`, `admin save|reboot|...`, `reboot`, `reload`, `shutdown`, `no shutdown`, `clear`, `reset`, `format`, `erase`, `destroy`, `tools dump|perform`, `debug`). No config-write tools exist. JSONL audit log of every command. No secret redaction. SNMP community passed as a plain tool param (defaults to `public`).

---

### 1.5 shigechika/eos-mcp (Arista eAPI)

| Field | Value |
|---|---|
| Repo / PyPI | https://github.com/shigechika/eos-mcp · https://pypi.org/project/eos-mcp/ (v1.3.0 uploaded 2026-08-15) |
| Framework | `mcp.server.fastmcp.FastMCP`, tools in `eos_mcp/server.py` **[src]**; pyeapi over HTTPS/443 to devices |
| Transport | stdio; also packaged as a Claude Code plugin (v1.3.0) |
| Device targeting | `hostname: str` param (must exist in `~/.config/eos-mcp/config.ini` or `EOS_MCP_CONFIG`); entries carry creds and optional tags; batch tools take `hostnames: list[str] | None` and/or `tags: list[str] | None` (default = all devices). Every tool also takes `config_path: str = ""` to override the inventory file. |
| Install | `pip install eos-mcp`; entry point `eos-mcp` |
| Stars / license | 0 stars, Apache-2.0 |
| Last activity | v1.3.0 2026-08-15 (steady releases Jul–Aug 2026) |

Tools **[src]**:

| Tool | Params | Class |
|---|---|---|
| `health_check` | `config_path=""` | LOCAL_ADMIN |
| `get_router_list` | `tags: list[str]|None`, `config_path` | INVENTORY_READ |
| `get_device_facts` / `get_version` | `hostname: str` | READ_OPERATIONAL |
| `get_device_facts_batch` | `hostnames?`, `tags?`, `max_workers=5` | READ_OPERATIONAL |
| `run_command` | `hostname: str`, `command: str` | EXEC_ARBITRARY (README admits verbatim pass-through to eAPI, incl. `configure`/`reload`) |
| `run_commands` | `hostname`, `commands: list[str]` | EXEC_ARBITRARY |
| `run_command_batch` | `command`, `hostnames?`, `tags?`, `max_workers=5` | EXEC_ARBITRARY (fleet-wide) |
| `run_commands_batch` | `commands: list[str]`, `hostnames?`, `tags?`, `max_workers=5` | EXEC_ARBITRARY (fleet-wide) |
| `get_config` | `hostname` | READ_CONFIG |
| `get_config_diff` | `hostname`, `rollback_id: int=1` | READ_CONFIG |
| `list_config_sessions` | `hostname` | READ_CONFIG |
| `push_config` | `hostname`, `config_lines: list[str]`, `session_name="mcp-push"`, `dry_run: bool=True`, `commit_timer: int=300` | WRITE_CONFIG (dry-run default; commit-timer rollback) |
| `confirm_config_session` | `hostname`, `session_name="mcp-push"` | WRITE_CONFIG (finalize) |
| `abort_config_session` | `hostname`, `session_name` | WRITE_CONFIG (rollback) |
| `collect_tech_support` | `hostname` | READ_OPERATIONAL (heavy) |
| `daily_brief` | `hostnames?`, `tags?`, `max_workers=5`, `since_hours=24` | READ_OPERATIONAL |

Safety: `push_config` defaults to `dry_run=True` and, when applied, uses an EOS configure session with commit timer requiring `confirm_config_session`. README explicitly documents that the `run_command*` family is an unrestricted second write path and recommends a show-only eAPI account. No command filtering, no redaction.

---

### 1.6 Arista CloudVision MCP (noredistribution/mcp-cvp-fun)

| Field | Value |
|---|---|
| Repo | https://github.com/noredistribution/mcp-cvp-fun (the `arista-cloudvision` URL in hecisaza's list 404s; PulseMCP entry https://www.pulsemcp.com/servers/noredistribution-arista-cloudvision points here) |
| Framework | Python, FastMCP (run via `uv run --with fastmcp fastmcp run`) **[doc]** |
| Transport | stdio (Claude Desktop config) |
| Target | CloudVision (cloud or on-prem) via env `CVP` (hostname) and `CVPTOKEN` (service-account token); single controller per server instance, no per-call host param |
| Tools **[doc]** | Device inventory retrieval; connectivity-monitor / health data; system events; tag creation for Studios/dashboards (write). Exact names/params not recoverable from README *(uncertain)*; main file `mcp_server_rest.py`. |
| Class | READ_OPERATIONAL (inventory, events, connectivity) + WRITE_CONFIG (tag create — controller metadata rather than device config) |
| Safety | README warns against production use; no read-only mode. |
| Stars / license | 5 stars, Apache-2.0, 7 commits; date *(uncertain)* |

---

### 1.7 Juniper/junos-mcp-server (official Juniper)

| Field | Value |
|---|---|
| Repo | https://github.com/Juniper/junos-mcp-server |
| Framework | Low-level official Python SDK `mcp.server.Server` with hand-written `list_tools()` JSON schemas and a `TOOL_HANDLERS` registry (single file `jmcp.py`, ~2,300 lines); PyEZ (junos-eznc) for device access with a connection pool **[src]** |
| Transport | `--transport stdio` or `streamable-http` (default; host 127.0.0.1, port 30030). HTTP fails closed unless a `.tokens` file exists or `--allow-unauthenticated-http` on loopback **[src]** |
| Device targeting | `-f devices.json` mapping of router **name** → connection params (ip, port, username, password or ssh key). Tools take `router_name` / `router_names`. |
| Install | `uv run python jmcp.py -f devices.json -t stdio`; Dockerfile documented (`junos-mcp-server:latest`) |
| Stars / license | 108 stars, 52 forks, Apache-2.0 |
| Last activity | v1.1.1 released May 5 (year not shown; 2026 likely) *(uncertain)*; 99 commits |

Tools **[src: list_tools()]**:

| Tool | Params (inputSchema) | Class |
|---|---|---|
| `execute_junos_command` | `router_name: string` (req), `command: string` (req), `timeout: integer=360` | EXEC_ARBITRARY (blocklist-filtered via `block.cmd`) |
| `execute_junos_pfe_command` | `router_name`, `target: string` (fpc0…), `command`, `timeout=360` | EXEC_ARBITRARY (PFE shell — high risk) |
| `execute_junos_command_batch` | `router_names: string[]`, `command`, `timeout=360` | EXEC_ARBITRARY (fleet-wide) |
| `get_junos_config` | `router_name` | READ_CONFIG |
| `junos_config_diff` | `router_name`, `version: integer=1` (rollback 1–49) | READ_CONFIG |
| `gather_device_facts` | `router_name`, `timeout=360` | READ_OPERATIONAL |
| `get_router_list` | none | INVENTORY_READ |
| `load_and_commit_config` | `router_name`, `config_text: string`, `config_format: string="set"` (set/text/xml), `commit_comment: string` | WRITE_CONFIG (immediate commit) |
| `render_and_apply_j2_template` | `template_content: string` (req), `vars_content: string` (YAML, req), `router_name?`, `router_names?: string[]`, `apply_config: boolean=false`, `dry_run: boolean=false`, `commit_comment`, `config_format?: enum[set,text,xml]`, `timeout=360` | Render-only by default; WRITE_CONFIG when `apply_config=true`; `dry_run=true` → commit-check + rollback (READ_CONFIG-ish) |

Safety **[src + README]**:
- `block.cfg`: regex patterns applied line-by-line to candidate config before `load_and_commit_config`; missing file → refuse to commit (fail closed).
- `block.cmd`: regex prefix patterns applied to `execute_junos_command` / batch; missing file → refuse to execute (fail closed). Example entries: reboot, zeroize.
- HTTP token auth (`.tokens` file, `jmcp_token_manager.py`), fail-closed on non-loopback bind.
- README recommends SSH key auth. No secret redaction. Juniper's Mist MCP docs (hosted, https://mcp.ai.juniper.net/mcp/mist) warn that PSKs/RADIUS/SNMP secrets can reach the assistant.

---

### 1.8 Palo Alto PAN-OS servers

#### 1.8a cdot65/pan-os-mcp

| Field | Value |
|---|---|
| Repo | https://github.com/cdot65/pan-os-mcp |
| Framework | Python, FastMCP from the official SDK **[doc]** |
| Transport | SSE (`/sse`, `/messages/`) via `python -m palo_alto_mcp`; stdio mentioned for client integration |
| Target | Single firewall/Panorama per instance via env `PANOS_HOSTNAME`, `PANOS_API_KEY` |
| Tools **[doc]** | `show_system_info()`, `retrieve_address_objects()`, `retrieve_security_zones()`, `retrieve_security_policies()` — no params beyond ambient env |
| Class | READ_OPERATIONAL / READ_CONFIG only |
| Safety | Inherently read-only; no redaction; stars/date not captured *(uncertain)* |

#### 1.8b apius-tech/Palo-MCP

| Field | Value |
|---|---|
| Repo | https://github.com/apius-tech/Palo-MCP (npm, `.mcpb` desktop extension) |
| Framework | TypeScript/Node 22+, official TS SDK with Zod schemas **[doc]** |
| Transport | stdio (npx / Claude Desktop extension) |
| Target | Single: env `PANOS_HOST` + `PANOS_API_KEY`; multi: `~/.config/panos-mcp/firewalls.json` with named entries, tools take optional `firewall: string` (required in multi mode); `list_firewalls` tool |
| Tools | 117 tools in 16 modules (system, network, security rules CRUD, objects CRUD, NAT CRUD, User-ID, admin, VPN, Panorama device-groups/templates, logs, threat, certificates, licenses, config, utility). Config module: `set_config`, `delete_config`, `commit`, Panorama commit/push. Utility: arbitrary `op` command runner and XPath read. |
| Labels | Every tool description carries `[READ-ONLY]`, `[MODIFIES CONFIG]` or `[ADVANCED]` — a ready-made classification a proxy can parse |
| Class | READ_OPERATIONAL/READ_CONFIG (majority), WRITE_CONFIG (CRUD + commit, staged), EXEC_ARBITRARY (`op` command, XPath) |
| Safety | Staged candidate config + explicit `commit`; Zod validation; recommends read-only API keys; no redaction |
| Stars / license / activity | 24 stars, MIT, v1.3.30 released 04 Sep (2026 implied) |

---

### 1.9 FortiGate servers

#### 1.9a rsp2k/mcfortigate (read-only)

| Field | Value |
|---|---|
| Repo / PyPI | https://github.com/rsp2k/mcfortigate · PyPI `mcfortigate` 2026.9.12.1 uploaded 2026-09-12 |
| Framework | Python, FastMCP **[doc]** |
| Transport | stdio (`uvx mcfortigate`) |
| Target | env `FORTIGATE_HOST`+`FORTIGATE_TOKEN`, or `FORTIGATE_TARGETS` JSON of aliases; tools take `target: str` alias; `FORTIGATE_VDOM`, `FORTIGATE_VERIFY_SSL` etc. |
| Tools **[doc]** | `list_targets()`, `get_system_status(target)`, `search_config(term, target)`, `list_address_objects/list_address_groups/list_services/list_policies/list_vips(limit, offset, target)`, `find_references(object_name, target)`, `list_interfaces/list_vlans/list_static_routes/get_routing_table(target)`, `list_wifi_clients/list_dhcp_leases/get_arp_table(limit, offset, target)`, `find_device(mac|ip|hostname, target)` |
| Class | READ_CONFIG + READ_OPERATIONAL only |
| Safety | No write tools; docs require a read-only REST admin profile; 0 stars, Apache-2.0 |

#### 1.9b oscardagrach/fortigate-mcp (read/write)

| Field | Value |
|---|---|
| Repo | https://github.com/oscardagrach/fortigate-mcp |
| Framework | TypeScript/JS, described as built with the Claude Agent SDK **[doc]** *(uncertain)* |
| Transport | stdio *(uncertain)* |
| Target | env `FORTIGATE_HOST`, `FORTIGATE_API_TOKEN`, `FORTIGATE_PORT`, `FORTIGATE_VERIFY_SSL`; all tools accept optional `vdom` |
| Tools | 393 tools: `get_*` readers (system status, interfaces, firewall policies, routing table, BGP, IPsec, SSL-VPN, DNS, sessions) and `create_*/update_*/delete_*` writers (policies, interfaces, static routes, BGP, IPsec, addresses, DNS) — FortiOS REST writes apply immediately (no commit stage) |
| Class | READ_* and WRITE_CONFIG; no EXEC_ARBITRARY |
| Safety | Only FortiOS admin-profile scoping; 0 stars, MIT |

Others found (not catalogued): alpadalar/fortigate-mcp-server, ofaruk89 & paoloamato2 `fortinet-mcp-server` (FortiOS 7.6 REST), rstierli/fortimanager-mcp, neetora/mcp-forti. Fortinet's official MCP is embedded in FortiWeb 8.0 / FortiManager 8.0 (product docs only, no repo).

---

### 1.10 Cisco

| Server | Repo | Notes |
|---|---|---|
| Cisco Meraki MCP (official) | https://github.com/CiscoDevNet/cisco-meraki-mcp-official | Python 3.14+/uv; HTTP (hosted) + stdio. Only **2 tools**: `semantic_search(query, top_k)` and `execute_api(capability_id, parameters)` — a meta-tool pattern where the real operation is chosen by `capability_id`. Read-only per README; recommends read-only Meraki API key. 1 star, Apache-2.0. Proxy implication: policy must inspect `capability_id`, not the tool name. |
| Cisco Catalyst Center MCP (official) | Docs only: https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/catalyst-center/223278-harness-the-power-of-mcp-servers.html | Enterprise package with OIDC/Duo, OPA policy, Vault; no public repo found *(uncertain)*. Community alternative: https://github.com/richbibby/catalyst-center-mcp — FastMCP, stdio, env `CCC_HOST/CCC_USER/CCC_PWD`, 7 read-only tools (`fetch_devices`, `fetch_sites`, `fetch_interfaces`, `get_clients_list`, `get_client_details_by_mac`, `get_clients_count`, `get_api_compatible_time_range`), 15 stars, Unlicense. |
| Catalyst SD-WAN (vManage) MCP | https://github.com/CiscoDevNet/catalyst-sdwan-mcp-community | TypeScript, Docker; env `VMANAGE_HOST/USERNAME/PASSWORD`; 39 tools, mostly read (`list_devices`, `get_control_connections`, `get_bfd_summary`) plus template/policy writes; no read-only mode; 8 stars, MIT. |
| Cisco multidomain inventory | https://github.com/CiscoDevNet/Cisco-multidomain-inventory-community | ACI/Meraki/SD-WAN inventory with MCP interface; read-focused (not deep-dived). |
| ThousandEyes MCP (official) | https://github.com/CiscoDevNet/ThousandEyes-MCP-Server-official | Monitoring/tests; not a device-config surface. |
| pyATS MCP (community, Capobianco) | https://github.com/automateyournetwork/pyATS_MCP | Python, stdio JSON-RPC, Docker. Targets via pyATS `testbed.yaml` (device names). Tools: `pyats_list_devices`, `pyats_search_devices(name)`, `pyats_run_show_command(device, command)`, `pyats_run_show_command_on_multiple_devices(devices[], command)`, `pyats_ping_from_network_device(device, target)`, `pyats_run_linux_command(host, command)`, `pyats_configure_device(device, commands[])`, `pyats_configure_devices_multi(devices[], commands[])`, `pyats_configure_with_diff(device, commands[])`, `pyats_rollback_config(device)`, `pyats_device_health`, `pyats_get_neighbors`, `pyats_find_interface_by_ip(device, ip)`, `pyats_run_dynamic_test(script)`, `pyats_get_operation_log`. Safety: show-command validation (blocks pipes/redirects/dangerous words), config blocklist (`reload`, `erase`, `write erase`, `delete`, `format`), sandboxed scripts. 76 stars, MIT. |
| Nexus Dashboard MCP | https://github.com/beye91/nexus-dashboard-mcp | FastAPI + Next.js, SSE; 638+ operations generated from OpenAPI; read-only by default, `EDIT_MODE_ENABLED` gate; RBAC roles, audit log, Docker Compose + Postgres; 9 stars, Apache-2.0. |
| Network MCP Docker Suite | https://github.com/pamosima/network-mcp-docker-suite | Ten FastMCP servers over HTTP (ports 8000–8009): Meraki, NetBox, Catalyst Center, IOS-XE (SSH), ThousandEyes, ISE, Splunk, Prometheus, ClickHouse, GitLab; non-root, no-new-privileges; 48 stars; v1.4.3 2026-05-29; Cisco Sample Code License. IOS-XE server tool names not extracted *(uncertain)*. |

No standalone official Cisco NX-OS device MCP server was found; NX-OS is covered by the generic SSH servers (netdev-ssh-mcp, netmiko, mcp-telecom) and Nexus Dashboard MCP.

---

### 1.11 Source-of-truth servers

| Server | Repo | Framework / transport | Tools | Class | Safety | Stats |
|---|---|---|---|---|---|---|
| NetBox MCP (NetBox Labs community) | https://github.com/netboxlabs/netbox-mcp-server | `fastmcp.FastMCP`; stdio default, `--transport http` with optional bearer-token verifier; warns when bound to 0.0.0.0 **[src: src/netbox_mcp_server/server.py]**; Docker Hub image `netboxlabs/netbox-mcp-server` | `netbox_get_objects(object_type: str, filters: dict, fields?: list[str], brief=False, limit: 1..100=5, offset≥0=0, ordering?)`, `netbox_get_object_by_id(object_type, object_id: int, fields?, brief)`, `netbox_get_changelogs(filters: dict)`, `netbox_search_objects(query: str, object_types?: list[str], fields?, limit)` **[src]** | INVENTORY_READ | Read-only by design; env `NETBOX_URL`/`NETBOX_TOKEN`; filter validation | 224 stars, Apache-2.0 |
| NetBox MCP RW (community) | https://github.com/alexkiwi1/netbox-mcp-rw | FastMCP, Python 3.13+ | Read: same three; Write: `netbox_create_object`, `netbox_update_object`, `netbox_delete_object`, plus `netbox_bulk_{create,update,delete}_objects` | INVENTORY_READ + INVENTORY_WRITE | Token in env; relies on NetBox changelog | 15 stars, Apache-2.0 |
| NetBox Platform MCP (official, hosted) | https://netboxlabs.com/docs/cloud/platform-mcp-server/ | Managed, HTTP bearer (`nbt_*` tokens) | CRUD, bulk, GraphQL, branching | READ + WRITE | Read-only mode on request | n/a |
| Nautobot MCP (official NTC) | https://docs.nautobot.com/projects/nautobot-mcp-server/en/stable/ ; repo https://github.com/networktocode-llc/nautobot-mcp-server (customers-only) | Not inspectable | Natural-language queries over devices/IPAM/VLANs | INVENTORY_READ | Authenticated API | n/a |
| Nautobot community | https://github.com/gt732/nautobot-app-mcp, https://github.com/bsmeding/nautobot-mcp-server, https://github.com/kvncampos/nautobot_mcp | Nautobot plugins / standalone (stdio+HTTP, RAG) | Not deep-dived | INVENTORY_READ mostly | *(uncertain)* | |

---

### 1.12 Batfish and containerlab

| Server | Repo | Notes |
|---|---|---|
| Batfish MCP Container (Presidio Federal) | Listing only: https://lobehub.com/mcp/presidio-federal-batfish-mcp-container ; no public GitHub repo located *(uncertain)*. Related: https://github.com/Presidio-Federal/network-discovery-mcp (FastAPI + MCP over HTTP 8080/443, Docker Compose, Batfish as a service dependency; tools `seed_device`, `scan_targets`, `scan_from_subnets`, `fingerprint_devices`, `collect_device_configs`, `validate_device_credentials`, `generate_topology_visualization`, `resume_failed_job`; 3 stars). | Batfish tools operate on offline snapshots → READ_CONFIG/analysis; never touch live devices. |
| clab-mcp-server (FloSch62) | https://github.com/FloSch62/clab-mcp-server | Go, talks to containerlab API server (`API_SERVER_URL`, default http://localhost:8080); tools: list labs, deploy, inspect, exec on node, destroy (names/params not documented) *(uncertain)*; 12 stars; no license. |
| clab-mcp-server (seanerama) | https://github.com/seanerama/clab-mcp-server | Python FastMCP, stdio; tools `authenticate`, `listLabs()`, `deployLab(topologyContent: object)`, `inspectLab(labName: string, details: boolean)`, `execCommand(labName, nodeName, command: string)`, `destroyLab(labName, cleanup: boolean, graceful: boolean)`; 4 stars, MIT. |
| Others | https://github.com/baijuw/clab-mcp-server, https://github.com/giancarlo3g/clab-mcp ; upstream API: https://github.com/srl-labs/clab-api-server | |

Class mapping: `listLabs`/`inspectLab` → READ_OPERATIONAL; `deployLab`/`destroyLab` → LAB_LIFECYCLE (destructive); `execCommand` → EXEC_ARBITRARY (shell on lab node).

---

### 1.13 Other entries from the hecisaza list (not device-CLI surfaces; noted for completeness)

HPE Aruba Central MCP (https://github.com/KarthikSKumar98/central-mcp-server, read-only), HPE unified (https://github.com/nowireless4u/hpe-networking-mcp), Splunk MCP (https://github.com/CiscoDevNet/Splunk-MCP-Server-official), Puppet Edge (YANG via Puppet Enterprise, docs only), Itential MCP (commercial, RBAC/compliance), Topolograph (OSPF/IS-IS visualisation), Juniper Mist hosted MCP (https://mcp.ai.juniper.net/mcp/mist).

---

## Part 2 — Synthesis

### 2(a) Common tool shapes and how they differ

**Shape 1: "run an operational command" (free-form string to device).** Present in nearly every CLI-backed server; this is the single most important surface for a proxy.

| Server | Tool name | Target param | Command param | Extras | Server-side filtering |
|---|---|---|---|---|---|
| netdev-ssh-mcp | `run_show_command` | `host` (+`device_type`) | `command` | `username`,`port` | allow-prefix `show`/`get`, config reads redirected |
| scrapli-mcp | `execute_ssh_command` | `host` (alias) | `command` | – | none |
| upa netmiko | `send_command_and_get_output` | `name` | `command` | – | opt-in prefix blocklist (`--secured`) |
| ntunes netmiko | `send_command` / `_parallel` / `_sequence` | `device` / `devices[]` (+`@group`) | `command` / `commands[]` | `use_textfsm`, `read_timeout`, `max_concurrent`, `stop_on_error` | none |
| mcp-telecom | `run_command` / `parallel_command` | `device` / `devices` (CSV string) | `command` | `max_workers` | allow-prefix + regex blocklist |
| eos-mcp | `run_command(s)` / `_batch` | `hostname` / `hostnames[]`+`tags[]` | `command` / `commands[]` | `max_workers`, `config_path` | none (documented as a write path) |
| junos-mcp | `execute_junos_command` / `_batch` / `_pfe_command` | `router_name` / `router_names[]` | `command` (+`target` for PFE) | `timeout` | `block.cmd` regex blocklist (fail-closed) |
| pyATS MCP | `pyats_run_show_command` / `_on_multiple_devices` | `device` / `devices[]` | `command` | – | show validation (pipes, redirects, keywords) |
| Palo-MCP | `op` utility tool | `firewall?` | XML/op string | – | labelled `[ADVANCED]` |

Differences a normalizer must absorb: the target key is variously `host`, `hostname`, `name`, `device`, `router_name`, `target`, `firewall`; batch variants use `devices`, `hostnames`, `router_names` (arrays) or a comma-separated string (`mcp-telecom`) or `@group` tokens (ntunes) or `tags` (eos-mcp); the command key is `command` vs `commands[]`. Only three servers (netdev-ssh-mcp, mcp-telecom, pyATS) enforce a *positive* allow-list; junos and upa use blocklists; the rest pass through.

**Shape 2: "get config".** `get_config(host, config_type)` (netdev-ssh-mcp, redacted), `get_config(hostname)` + `get_config_diff(hostname, rollback_id)` (eos-mcp), `get_junos_config(router_name)` + `junos_config_diff(router_name, version)` (junos), `backup_config(device)` + `compare_configs(device, backup_file)` + `netconf_get_config(device, source)` (mcp-telecom), `retrieve_security_policies()` etc. (PAN-OS), `list_policies(target)` / `search_config(term, target)` (mcfortigate). Netmiko-based servers have **no** dedicated config-read tool — the model is expected to type `show running-config` into the command tool, which is why netdev-ssh-mcp deliberately redirects those strings.

**Shape 3: "send config".** `set_config_commands_and_commit_or_save(name, commands[])` (upa; auto-commit+save), `send_config(device, config_commands[], save_config, dry_run, enter_config_mode)` + `_parallel(..., rollback_on_error)` (ntunes), `push_config(hostname, config_lines[], session_name, dry_run=True, commit_timer)` + `confirm_config_session` / `abort_config_session` (eos-mcp; two-phase), `load_and_commit_config(router_name, config_text, config_format, commit_comment)` and `render_and_apply_j2_template(..., apply_config, dry_run)` (junos; single-phase commit, template variant supports commit-check), `pyats_configure_device(device, commands[])` / `_with_diff` / `_rollback_config` (pyATS), `set_config`/`delete_config` + `commit` (Palo-MCP; staged), `create_*/update_*/delete_*` (fortigate-mcp; immediate). The payload is variously `commands: list[str]`, `config_commands`, `config_lines`, or a single `config_text`/`template_content` string with a `config_format` enum. Dry-run semantics differ: eos-mcp is dry-run *by default*; ntunes and junos require opt-in; upa and fortigate-mcp have none.

**Shape 4: inventory/discovery.** `get_network_device_list()`, `list_devices(tag?, device_type?)`, `get_router_list(tags?)`, `list_targets()`, `list_firewalls()`, `pyats_list_devices()`, `list_devices()` — all parameterless or filter-only, safe, and useful to the proxy for building its own allow-list of targets at startup.

**Shape 5: reachability probes.** `run_ping`/`run_traceroute` (netdev-ssh-mcp, richly parameterised), `pyats_ping_from_network_device(device, target)`, `health_check`/`test_connection`. Only netdev-ssh-mcp models ping/traceroute as first-class tools with typed args; the others expect them via the free-form command tool.

**Shape 6: canned/typed show tools.** mcp-telecom (`show_bgp_summary(device)` ×~20, vendor-mapped), mcfortigate (`list_policies`, `get_routing_table`), cdot65 pan-os (`retrieve_address_objects`), Palo-MCP (117 typed tools), fortigate-mcp (393 typed tools), Nexus Dashboard (638 OpenAPI-generated). These are easiest to police because the tool name alone determines the class.

**Shape 7: meta-tool / capability dispatch.** Cisco Meraki official: `execute_api(capability_id, parameters)`; the tool name carries no semantics and the proxy must classify on `capability_id`.

### 2(b) Best first integrations for a proxy

Ranked by: stdio available, containerizable, multi-vendor, active, and having a tool surface that is small enough to enumerate exhaustively.

1. **krisiasty/netdev-ssh-mcp** — single Go binary, stdio, 5 vendors, 5 tools with typed JSON schemas, already read-only with redaction. Ideal as the *reference read-only backend*; the proxy's main job is host allow-listing (since `host` is free-form) and rate/size limits. Low star count is the only concern.
2. **Juniper/junos-mcp-server** — official vendor server, 108 stars, stdio + streamable-HTTP with token auth, Dockerfile, explicit `block.cfg`/`block.cmd` guardrails and a clean 9-tool surface with hand-written JSON schemas. Best candidate for exercising WRITE_CONFIG policy (commit-check vs commit, template apply) in a proxy.
3. **ntunes/netmiko-mcp-server** — stdio + streamable-HTTP, Docker, YAML inventory with groups/tags, cleanly separated read/config tool modules, but *no* built-in safety → the proxy adds the most value here. Small community (4 stars) is a risk; **upa/mcp-netmiko-server** (35 stars) is the fallback with a 3-tool surface and `--disable-config`/`--secured` flags the proxy could rely on as defence-in-depth.
4. **shigechika/eos-mcp** — actively released (Aug 2026), PyPI install, stdio, exemplary two-phase config push, honest documentation of its unrestricted `run_command*` path. Good for validating that the proxy correctly classifies `run_command` as EXEC_ARBITRARY despite its innocuous name.
5. **mcp-telecom** — broadest vendor list (incl. Nokia SR OS, IOS-XR) and a reusable allow-list/blocklist (`safety.py`) plus JSONL audit; 60-tool surface is large but almost all typed/canned; Docker provided. Concern: 1 star, single maintainer.
6. **apius-tech/Palo-MCP** and **rsp2k/mcfortigate** as the firewall pair: both stdio, npm/PyPI installs, recent releases (Sep 2026), and Palo-MCP's `[READ-ONLY]/[MODIFIES CONFIG]/[ADVANCED]` labels can be parsed straight into the proxy classification.
7. **netboxlabs/netbox-mcp-server** — most popular (224 stars), read-only, Docker Hub image; low-risk first target for the "source of truth" side and a handy way for the proxy to validate that a requested `host` exists in inventory.

Deprioritise: scrapli-mcp (one-commit demo, leaks credentials via resource), mmaeso/mcp-server-scrapli (dead), melihteke/Michaelbecze netmiko demos, CloudVision demo (7 commits), Meraki official (meta-tool makes name-based policy impossible; needs capability catalog), Nexus Dashboard (its own RBAC/audit layer overlaps with the proxy).

### 2(c) Proposed normalized classification

Proposed classes (superset of the four requested, because inventory/lab operations do not fit cleanly):

| Class | Definition | Default policy suggestion |
|---|---|---|
| `READ_OPERATIONAL` | Returns device/controller state; no persistence change. Includes ping/traceroute, facts, typed show tools, and free-form commands **after** the proxy verifies a `show`/`get`/`display`/`ping`/`traceroute` allow-list. | Allow; log; redact secrets in output. |
| `READ_CONFIG` | Returns running/startup/candidate config or diffs, compliance/backups. Highest secret-leak risk. | Allow with mandatory redaction (deterministic tokens as netdev-ssh-mcp does, but keyed HMAC per invariant 4; see the §1.1 update of 2026-09-23); optional deny for `startup`. |
| `WRITE_CONFIG` | Modifies device or controller configuration, including staged commits, confirms, aborts, rollbacks and SoT/tag writes. | Deny by default; allow with change-ticket / human approval; force `dry_run=true` first where the tool has it; cap fleet fan-out. |
| `EXEC_ARBITRARY` | Free-form command execution that is not filtered by the server (or is filtered only by a blocklist), PFE/shell access, lab-node exec, XML `op`/XPath. | Deny by default; or rewrite into READ_OPERATIONAL when the string passes the proxy allow-list, else block. |
| `INVENTORY_READ` (aux) | Lists devices/groups/tags/capabilities; no device contact or SoT reads. | Allow; use to seed the target allow-list. |
| `LAB_LIFECYCLE` / `LOCAL_ADMIN` (aux) | Deploy/destroy labs, trust host keys, start dashboards, telemetry subscriptions. | Case-by-case; treat destroy as WRITE. |

Mapping of surveyed tools:

| Class | Tools |
|---|---|
| READ_OPERATIONAL | netdev-ssh-mcp `run_show_command`, `run_ping`, `run_traceroute`; mcp-telecom all `show_*`, `run_command`, `parallel_command`, `run_vendor_operation`, `health_check`, `netconf_get_operational`, `snmp_*`, topology tools; eos-mcp `get_device_facts(_batch)`, `get_version`, `daily_brief`, `collect_tech_support`; junos `gather_device_facts`; ntunes `test_connection`; pyATS `pyats_run_show_command*`, `pyats_ping_from_network_device`, `pyats_device_health`, `pyats_get_neighbors`, `pyats_find_interface_by_ip`; cdot65 `show_system_info`; mcfortigate `get_system_status`, `get_routing_table`, `list_wifi_clients`, `list_dhcp_leases`, `get_arp_table`, `find_device`; Palo-MCP `[READ-ONLY]` system/network/logs/threat tools; Catalyst Center `fetch_*`, `get_clients_*`; clab `listLabs`, `inspectLab` |
| READ_CONFIG | netdev-ssh-mcp `get_config`; eos-mcp `get_config`, `get_config_diff`, `list_config_sessions`; junos `get_junos_config`, `junos_config_diff`, `render_and_apply_j2_template` with `apply_config=false` or `dry_run=true`; mcp-telecom `backup_config`, `compare_configs`, `netconf_get_config`, `compliance_*`; cdot65 `retrieve_address_objects/security_zones/security_policies`; mcfortigate `search_config`, `list_address_objects/groups/services/policies/vips`, `find_references`, `list_interfaces/vlans/static_routes`; Palo-MCP `[READ-ONLY]` security/objects/NAT/Panorama readers and XPath read; fortigate-mcp `get_*`; Batfish snapshot queries |
| WRITE_CONFIG | upa `set_config_commands_and_commit_or_save`; ntunes `send_config`, `send_config_parallel`; eos-mcp `push_config` (when `dry_run=false`), `confirm_config_session`, `abort_config_session`; junos `load_and_commit_config`, `render_and_apply_j2_template` with `apply_config=true`; pyATS `pyats_configure_device`, `_devices_multi`, `_with_diff`, `pyats_rollback_config`; Palo-MCP `[MODIFIES CONFIG]` CRUD, `set_config`, `delete_config`, `commit`, Panorama push; fortigate-mcp `create_*/update_*/delete_*`; CloudVision tag creation; netbox-mcp-rw `netbox_create/update/delete_object` and bulk; SD-WAN template/policy writes; Nexus Dashboard writes when `EDIT_MODE_ENABLED` |
| EXEC_ARBITRARY | scrapli-mcp `execute_ssh_command`; upa `send_command_and_get_output` (unless `--secured`, and even then); ntunes `send_command`, `send_command_parallel`, `send_commands_sequence`; eos-mcp `run_command`, `run_commands`, `run_command_batch`, `run_commands_batch`; junos `execute_junos_command`, `execute_junos_command_batch`, `execute_junos_pfe_command`; pyATS `pyats_run_linux_command`, `pyats_run_dynamic_test`; Palo-MCP `[ADVANCED]` op-command tool; clab `execCommand`; Meraki `execute_api` (until `capability_id` is resolved) |
| INVENTORY_READ | upa `get_network_device_list`; ntunes `list_devices`, `get_device_info`, `list_groups`, `get_device_types`, `get_tags`, `get_pool_status`; eos-mcp `get_router_list`; junos `get_router_list`; mcp-telecom `list_devices`, `list_device_capabilities`, `get_audit_log`, `pool_stats`; mcfortigate `list_targets`; Palo-MCP `list_firewalls`; pyATS `pyats_list_devices`, `pyats_search_devices`, `pyats_get_operation_log`; netbox `netbox_get_objects`, `netbox_get_object_by_id`, `netbox_get_changelogs`, `netbox_search_objects`; Meraki `semantic_search` |
| LAB_LIFECYCLE / LOCAL_ADMIN | netdev-ssh-mcp `trust_host_key`; mcp-telecom `telemetry_subscribe/unsubscribe`, `clab_*`, `start_dashboard`, `start_metrics_endpoint`; eos-mcp `health_check`; clab `deployLab`, `destroyLab`, `authenticate` |

Normalization rules the proxy should apply on top of the class:
1. **Target canonicalisation**: map `host|hostname|name|device|router_name|target|firewall` → `target`; `devices|hostnames|router_names|hosts` (array), comma-separated `devices` strings, `@group` tokens and `tags` → `targets[]`; resolve every target against the proxy's own inventory allow-list and reject unknowns (critical for netdev-ssh-mcp whose `host` is free-form).
2. **Command canonicalisation**: map `command` / `commands[]` → `commands[]`; for EXEC_ARBITRARY tools, apply the union of the strongest existing filters — mcp-telecom's allow-prefix list + regex blocklist, pyATS's pipe/redirect ban, netdev-ssh-mcp's config-read redirection — and downgrade the call to READ_OPERATIONAL only if every command passes.
3. **Config payload canonicalisation**: `commands|config_commands|config_lines|config_text|template_content(+vars_content)` → `config_payload` with `format` (`set|text|xml|cli`); run junos-style `block.cfg` regexes; if the backend exposes `dry_run` or `apply_config`, force a dry-run pass before any real commit; cap `max_concurrent`/`max_workers`/target-list length for fleet-wide variants.
4. **Output redaction**: apply deterministic tokens in the style of netdev-ssh-mcp, keyed with HMAC (its own hash is unkeyed; §1.1 update of 2026-09-23), to all READ_CONFIG and READ_OPERATIONAL results (none of the other servers redact; Juniper's own Mist docs warn secrets flow to the model).
5. **Ambient-credential awareness**: most servers read credentials from env/inventory files, and the Meraki/PAN-OS/FortiGate ones bind one controller per process; the proxy must therefore run one backend instance per credential scope rather than expecting per-call auth.
6. **Meta-tool handling**: for `execute_api(capability_id, ...)`-style servers, maintain a capability→class table rather than a tool→class table.

---

## Sources (primary)

- https://github.com/hecisaza/network-mcp-servers (curated list, CC BY 4.0)
- https://github.com/krisiasty/netdev-ssh-mcp · raw `main.go`, `internal/netdev/show.go`, `config.go`, README
- https://github.com/carlmontanari/scrapli-mcp · raw `main.py`
- https://github.com/upa/mcp-netmiko-server · raw `main.py`
- https://github.com/ntunes/netmiko-mcp-server · raw `src/netmiko_mcp/server.py`, `tools/commands.py`, `tools/config_tools.py`, `tools/discovery.py`, README
- https://github.com/Avinash-Amudala/MCP-Telecom · raw `src/mcp_telecom/server.py`, `safety.py`; https://pypi.org/project/mcp-telecom/
- https://github.com/shigechika/eos-mcp · raw `eos_mcp/server.py`, README; https://pypi.org/project/eos-mcp/
- https://github.com/noredistribution/mcp-cvp-fun ; https://www.pulsemcp.com/servers/noredistribution-arista-cloudvision
- https://github.com/Juniper/junos-mcp-server · raw `jmcp.py`, README
- https://github.com/cdot65/pan-os-mcp ; https://github.com/apius-tech/Palo-MCP
- https://github.com/rsp2k/mcfortigate ; https://github.com/oscardagrach/fortigate-mcp
- https://github.com/CiscoDevNet/cisco-meraki-mcp-official ; https://github.com/richbibby/catalyst-center-mcp ; https://github.com/CiscoDevNet/catalyst-sdwan-mcp-community ; https://github.com/automateyournetwork/pyATS_MCP ; https://github.com/beye91/nexus-dashboard-mcp ; https://github.com/pamosima/network-mcp-docker-suite
- https://github.com/netboxlabs/netbox-mcp-server · raw `src/netbox_mcp_server/server.py` ; https://github.com/alexkiwi1/netbox-mcp-rw ; https://docs.nautobot.com/projects/nautobot-mcp-server/en/stable/
- https://lobehub.com/mcp/presidio-federal-batfish-mcp-container ; https://github.com/Presidio-Federal/network-discovery-mcp
- https://github.com/FloSch62/clab-mcp-server ; https://github.com/seanerama/clab-mcp-server
