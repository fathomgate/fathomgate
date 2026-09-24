# Test matrix

The 22 cases from [PLAN.md](../PLAN.md#test-matrix). Every case names the real upstream server it is validated against. Tier definitions are in [test-strategy.md](test-strategy.md). Status moves from `planned` to `passing` when the case runs green in CI; a case that is skipped for a licence reason is `skipped` with the reason.

| # | Case | Tier | Upstream server | Expected | Milestone | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `tools/list` passes through with server prefix | 2 | netdev-ssh-mcp | Tools appear as `netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config`, and so on (the prefix is the profile `server` key) | M0 | planned; ran locally against v1.6.6, see [run notes](#run-notes) |
| 2 | Dual-era handshake | 2 | netdev-ssh-mcp (go-sdk, 2026 era); upa/mcp-netmiko-server (FastMCP, 2025 era) | Both upstreams initialise; conformance suite green on the client-facing side | M0 | planned; conformance runs all four era pairs through netguard against go-sdk fixtures, not validated, see [run notes](#run-notes) |
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
| 22 | PATH-stripped launcher | 2 | Claude Desktop-style config with absolute binary path and empty `PATH`; netdev-ssh-mcp v1.6.6 behind netguard | Proxy starts and serves `tools/list`; no ENOENT | M0 | planned; ran locally against v1.6.6 (python-sdk client; Claude Code 2.1.236 `tools/list` only), not validated, see [run notes](#run-notes) |

## Run notes

Runs that moved a row forward without closing it. A row becomes `passing` only when its case runs green in CI against the named real server; rows 1 and 22 also need the manual real-client check in [install.md](../install.md#check-it-works) before M0 exit criterion 2 can be ticked.

**Rows 1 and 22, 2026-09-23 (T0.5).** Upstream: krisiasty/netdev-ssh-mcp v1.6.6, both the release binary `netdev-ssh-mcp_1.6.6_darwin_arm64` (sha256 `42b4f18a…b4493`, commit `be3e3634`) and a `go install …@v1.6.6` build. Device: `tests/fixtures/device/fake_ssh.py` (EOS persona, exec channel). netguard at `20781c7`, macOS arm64. `uv run --extra integration pytest integration -m tier2`: 11 passed, 2 skipped (the M1 cases).

- Row 1: `tests/integration/test_passthrough.py`. `tools/list` returns exactly the five upstream tools as `netdev-ssh-mcp.<tool>`, matching `profiles/netdev-ssh-mcp.yaml`. A read-only `tools/call` (`run_show_command`, `show version`) reaches the fake device once and returns the transcript unchanged. The upstream's own refusal of `reload` comes back as `isError` and nothing reaches the device. In M0 that is not a `deny`: netguard decides nothing yet. Client: python-sdk `mcp` 2.2.0.
- Row 22: `tests/integration/test_launcher_path.py`. With absolute paths, `PATH=""` and a fully empty environment (`env -i`), netguard serves `tools/list` and a read call. Every broken form fails fast with exit 1 and the cause on stderr, with no hang (under 1 s each): a bare `--upstream` name gives `executable file not found in $PATH`; a wrapper that looks up the server on `PATH` gives the upstream's `not found` line and then `connection closed: calling "initialize"`; netdev-ssh-mcp with no `HOME` and no `SSH_KNOWN_HOSTS` exits at startup. The `--upstream-env PATH=…` fix is tested.
- Real client: Claude Code 2.1.236 in print mode, with `--mcp-config --strict-mcp-config` and `"env": {"PATH": ""}`, reported the server `connected` and listed `mcp__netdev__netdev-ssh-mcp_run_show_command` and the other four tools (Claude Code turns the `.` into `_`). The model turn did not run, because the CLI had no working login in the test session, so no `tools/call` went through Claude Code. Cursor was not run, because it cannot be driven headless.
- CI: the `client-smoke` job ran the same suite green on the pull request, against the linux_amd64 release binary (sha256 `256ab497…75621`): [run 35947953383](https://github.com/joshscott13/netguard/actions/runs/35947953383/job/107470027880).
- To be `passing`: `client-smoke` green on `main`. To tick exit criterion 2: a person does the install.md check in Claude Code and in Cursor.

**Rows 1 and 15, 2026-09-23 (T0.26).** Upstream: krisiasty/netdev-ssh-mcp v1.6.6, a `go install …@v1.6.6` build (go1.27.1). Device: the fake SSH device with a new `show running-config` transcript: a real public Arista vEOS EOS-4.16.6M sample from HPE documentation, with its two SNMP communities and two type-5 hashes replaced by FAKE values (provenance in `tests/fixtures/device/README.md`). netguard at `2459c3a` plus this change, macOS arm64. `uv run --extra integration pytest integration -m tier2`: 13 passed, 2 skipped (the M1 cases), 1 xfailed (the row 15 case).

- Row 1: a read-config call through netguard. The upstream refuses `show run…` in `run_show_command` and points to `get_config`, so the test calls `netdev-ssh-mcp.get_config` (`device_type: eos`, `config_type: running`). The device receives one `show running-config | no-more`. The fake device now drops a trailing `| no-more` when it looks up a transcript.
- The upstream replaces secrets itself by default (`internal/netdev/obfuscate.go`): each value becomes `[h:<first 6 bytes of sha256, hex>]`. The test pins that: the agent gets the transcript with exactly four lines changed, and each one carries that hash. The hash has no key, so a guessable value such as the sample's original `public` can be recovered with a dictionary. It is not netguard's redaction and does not count toward row 15.
- With the upstream's `--no-obfuscate` (passed after `--`), the agent gets all four FAKE credentials unchanged. That is the M0 fact, and the test asserts it on purpose: `netguard serve` forwards results as they are.
- Row 15 (tier 1): the same text, with rule annotations, is the redaction fixture `tests/fixtures/configs/eos-4.16.txt`. `make fixtures-check` shows the redactor catches all four in EOS-4.16 syntax (`cisco-snmp-community` 2, `cisco-password-type` 2), with no hits anywhere else in the config. The original published values give the same four hits.
- Row 15 (tier 2): `test_running_config_redacted_by_netguard` is a strict xfail until the redactor runs at the response serialiser (ROADMAP M2). When it runs there, the case XPASSes, strict mode fails it, and `test_running_config_secrets_reach_agent_in_m0` fails with it. Flip both in that PR. Row 15 stays `planned`.

**Row 2, 2026-09-23 (T0.19).** Upstreams: go-sdk's conformance everything-server at v1.8.0 (the `go.mod` version; negotiates `2026-07-28` with netguard) and at v1.6.1 (the last release without `2026-07-28`; negotiates `2025-11-25`, logged as `upstream ready ... protocol=2025-11-25 era=stateful`). Suite `@modelcontextprotocol/conformance` 0.2.0-alpha.11. netguard at `b4c3b4e` (main, with T0.28 and T0.23) plus this change, macOS arm64. `make conformance PYTHON=python3`: every leg green against its baseline.

- 2025 agent x 2025 upstream (`netguard-up2025`, `--requirements 2025-11-25`): 14 of 30 scored scenarios clean, 50 scored checks passing, 16 baseline entries. `tools-call-elicitation` and `elicitation-sep1034-defaults` pass: the upstream's `elicitation/create` reaches the agent and the answer goes back. They stay baselined on the `netguard` leg, where the upstream is on `2026-07-28`. `elicitation-sep1330-enums` fails because go-sdk v1.8.0 (netguard's upstream client) refuses the fixture's `titledMulti` schema before netguard sees it, and netguard's allow-list would refuse it next (profile-schema section 8.4).
- 2026 agent x 2025 upstream (`netguard-up2025`, `--requirements 2026-07-28`): 12 of 37 scored scenarios clean, 65 scored checks passing, 42 baseline entries: 12 HTTP-transport checks (as on the control leg), 17 netguard decisions (as on the `netguard` leg), 13 checks that call 2026-era tools this upstream does not have. Listing, calls, content types, errors and progress cross the era boundary.
- `era_pairs.py`: for a 2025 agent the prompt arrives as `[from conf] <message>` and the accepted answer completes the tool; for a 2026 agent the call ends with `isError` and the exact ADR 0014 refusal, with no prompt shown. Both cells fail against the v1.8.0 fixture, so the check needs the 2025 upstream to pass.
- The existing legs are unchanged: `netguard` 12 of 30 (2025) and 18 of 37 (2026) scored scenarios clean, with 18 and 34 entries.
- Not validated: both upstreams are go-sdk fixtures. To be `passing`: netdev-ssh-mcp (go-sdk, 2026 era) and upa/mcp-netmiko-server (FastMCP, 2025 era) initialise behind netguard in tier 2 CI.

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
