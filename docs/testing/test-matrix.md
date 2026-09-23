# Test matrix

The 22 cases from [PLAN.md](../PLAN.md#test-matrix). Every case names the real upstream server it is validated against. Tier definitions are in [test-strategy.md](test-strategy.md). Status moves from `planned` to `passing` when the case runs green in CI; a case that is skipped for a licence reason is `skipped` with the reason.

| # | Case | Tier | Upstream server | Expected | Milestone | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `tools/list` passes through with server prefix | 2 | netdev-ssh-mcp | Tools appear as `netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config`, and so on (the prefix is the profile `server` key) | M0 | planned |
| 2 | Dual-era handshake | 2 | netdev-ssh-mcp (go-sdk, 2026 era); upa/mcp-netmiko-server (FastMCP, 2025 era) | Both upstreams initialise; conformance suite green on the client-facing side | M0 | planned |
| 3 | `show ip bgp summary` on lab device | 1, 2 | netdev-ssh-mcp `run_show_command` | Allowed; classified `READ_OPERATIONAL`; rule `reads-anywhere` | M1 | planned |
| 4 | `reload` via free-form command | 1, 2 | upa `send_command_and_get_output`; eos-mcp `run_command` | Denied by `no-exec`; tool error names the rule id | M1 | planned |
| 5 | `show running-config` through free-form tool | 2 | ntunes `send_command` | Reclassified `READ_CONFIG`; output redacted; `class_source: reclassify` | M1, M2 | planned |
| 6 | Unknown host | 1, 2 | netdev-ssh-mcp (free-form `host`) | Denied for writes and exec; audit event shows `unknown_target: true` and rule `defaults.unknown_target` | M1 | planned |
| 7 | Device tagged `lab`, config write | 2, 3 | eos-mcp `push_config` | Allowed with `dry_run` and `diff` obligations; commit timer set | M3 | planned |
| 8 | Device role `core`, config write | 2, 3 | junos-mcp-server `load_and_commit_config` | Held; pending record created; diff shown; rule `prod-core-needs-approval` | M3 | planned |
| 9 | Approve via CLI within TTL | 2 | junos-mcp-server | Executed once; audit carries `approver` and `approval_channel: cli` | M3 | planned |
| 10 | Approve after TTL | 1, 2 | junos-mcp-server | Expired; approve refused with `invalid_transition`; audit `decision: expired` | M3 | planned |
| 11 | Diff drift between hold and approve | 2 | junos-mcp-server | Cancelled; agent told to resubmit; `error_class: drift` | M3 | planned |
| 12 | MRTR elicitation approval | 2 | junos-mcp-server, 2026-era client | `input_required` returned with `requestState`; retry with `accept` forwards once | M3 | planned |
| 13 | Fan-out above cap | 1, 2 | ntunes `send_config_parallel`; junos `execute_junos_command_batch` | Denied by `fleet-cap`; `targets_count` reflects expanded targets | M4 | planned |
| 14 | Canary-first ordering | 2 | ntunes `send_config_parallel` | Second device refused until the `canary`-tagged device is confirmed | M4 | planned |
| 15 | Secret redaction on `get_config` | 1, 2 | netdev-ssh-mcp `get_config`; junos-mcp-server `get_junos_config` | Every fixture secret replaced with an HMAC token; `redactions` count and pattern ids logged | M2 | planned |
| 16 | Tool description rug-pull | 2 | Any server with a modified description | Server quarantined; `quarantine` audit event with pinned and observed hashes | M2 | planned |
| 17 | Upstream elicitation origin | 2 | junos-mcp-server (streamable-http) | Prompt re-labelled with the server name before reaching the client | M3 | planned |
| 18 | Meta-tool classification | 1 | Meraki official `execute_api` fixture | Class from the `capability_id` table; `class_source: capability_table` | M1 | planned |
| 19 | Audit tamper | 1 | none | `netguard audit verify` fails on an edited line and names it; exit status 1 | M4 | planned |
| 20 | Timed rollback fires | 3 | eos-mcp on cEOS | Unconfirmed configure session reverts at the timer; device state asserted over scrapli | M3 | planned |
| 21 | Watchdog rollback | 3 | netdev-ssh-mcp on NX-OS image | Checkpoint restored at the watchdog deadline | M5 | skipped until an NX-OS image is licensed on the runner |
| 22 | PATH-stripped launcher | 2 | Claude Desktop-style config with absolute binary path and empty `PATH` | Proxy starts and serves `tools/list`; no ENOENT | M0 | planned |

## Coverage by component

| Component | Cases |
| --- | --- |
| `internal/proxy` | 1, 2, 12, 16, 17, 22 |
| `internal/normalize` | 5, 6, 13, 18 |
| `internal/classify` | 3, 4, 5, 18 |
| `internal/inventory` | 6, 7, 8, 14 |
| `internal/policy` | 3, 4, 6, 7, 8, 13, 14 |
| `internal/approval` | 8, 9, 10, 11, 12 |
| `internal/safety` | 7, 8, 11, 20, 21 |
| `internal/redact` | 5, 15 |
| `internal/audit` | 6, 9, 10, 15, 16, 19 |

## Coverage by upstream

| Upstream | Cases |
| --- | --- |
| netdev-ssh-mcp | 1, 2, 3, 6, 15, 21 |
| junos-mcp-server | 8, 9, 10, 11, 12, 13, 15, 17 |
| upa/mcp-netmiko-server | 2, 4 |
| ntunes/netmiko-mcp-server | 5, 13, 14 |
| eos-mcp | 4, 7, 20 |
| Meraki official (fixture) | 18 |

Palo-MCP and mcfortigate validate the M5 firewall drivers and profiles; their cases are added to this table when M5 starts.
