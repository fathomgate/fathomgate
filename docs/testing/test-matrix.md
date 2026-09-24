# Test matrix

The 22 cases from [PLAN.md](../PLAN.md#test-matrix). Every case names the real upstream server it is validated against. Tier definitions are in [test-strategy.md](test-strategy.md). Status moves from `planned` to `passing` when the case runs green in CI; a case that is skipped for a licence reason is `skipped` with the reason.

| # | Case | Tier | Upstream server | Expected | Milestone | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `tools/list` passes through with server prefix | 2 | netdev-ssh-mcp | Tools appear as `netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config`, and so on (the prefix is the profile `server` key) | M0 | passing (client-smoke CI; Claude Code 2.1.236 and Claude Desktop 2.7032.0 by hand, 2026-09-23; see [run notes](#run-notes)) |
| 2 | Dual-era handshake | 2 | netdev-ssh-mcp (go-sdk, 2026 era); upa/mcp-netmiko-server (FastMCP, 2025 era) | Both upstreams initialise; conformance suite green on the client-facing side | M0 | passing (tier 2 CI on `main` at `51921ed`, 2026-09-24): netdev-ssh-mcp v1.6.6 initialises behind netguard at 2026-07-28; upa/mcp-netmiko-server `96e8ff3` initialises at 2025-11-25 with mcp 1.30.0, for a 2025-11-25 agent and a 2026-07-28 agent, and at 2024-11-05 on its own `uv.lock` (mcp 1.6.0) after netguard restarts it once and connects with `initialize` only ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)); `mcp-conformance` green. See [run notes](#run-notes) |
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
| 22 | PATH-stripped launcher | 2 | Claude Desktop-style config with absolute binary path and empty `PATH`; netdev-ssh-mcp v1.6.6 behind netguard | Proxy starts and serves `tools/list`; no ENOENT | M0 | passing (client-smoke CI; Claude Code 2.1.236 and Claude Desktop 2.7032.0 by hand, 2026-09-23; see [run notes](#run-notes)) |

## Run notes

One entry per run that changed a row's status or added evidence for it. A row becomes `passing` only when its case runs green in CI against the named real server; rows 1 and 22 also need the manual real-client check in [install.md](../install.md#check-it-works) before M0 exit criterion 2 can be ticked.
- **2026-09-23, rows 1 and 22 passing, M0 exit criterion 2 met.** Upstream `krisiasty/netdev-ssh-mcp` v1.6.6 (`go install`), netguard from `main`, fake EOS device (`tests/fixtures/device/fake_ssh.py`, port 22022). The maintainer asked each client, in plain words, for `show version` on `127.0.0.1` port 22022 device type `eos`; each answer contained `Serial number: FAKE0000SN01`, and the device's `commands.log` recorded exactly one `show version` per client (two lines in total).
  - **Claude Code 2.1.236**, `claude mcp add` with absolute paths, run from a terminal.
  - **Claude Desktop 2.7032.0**, `claude_desktop_config.json` with absolute paths, started from the Dock (the PATH-stripped launch, row 22).
  - CI job `tier2 client smoke (netdev-ssh-mcp)` green on `main` at `b4c3b4e`.
  - Cursor was not installed on the test Mac; Claude Desktop is the second client. Cursor stays documented in `docs/install.md` but unexercised.


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
- Not validated: both upstreams are go-sdk fixtures. To be `passing`: netdev-ssh-mcp (go-sdk, 2026 era) and upa/mcp-netmiko-server (FastMCP, 2025 era) initialise behind netguard in tier 2 CI. Met since T0.34; see the T0.39, T0.41 entry.

**Row 2, 2026-09-24 (T0.34).** Upstream: upa/mcp-netmiko-server at commit `96e8ff321cc839eeb525474736439ddc2ebc795c` (2025-05-30; the project has no releases). The server is one file, `main.py`, sha256 `07e55298409e91dea62e2f245fad37be75e71a0dd8df9027f97ba0c7cca7babb`: FastMCP from the Python SDK, over stdio. `tests/integration/upstreams/upa-mcp-netmiko-server/install.sh` fetches that commit and builds two Python 3.13 environments, described in the bullets below. Device: the fake SSH device's new interactive shell, driven by netmiko 4.5.0 as `arista_eos`. netguard at `279d3b2` (main) plus this change, on macOS arm64. Clients: raw JSON-RPC in each era, and python-sdk `mcp` 2.2.0. `pytest integration -m "tier2 and upa_mcp_netmiko_server"`: 7 passed, 1 xfailed (strict), in about 40 s. `-m "tier2 and netdev_ssh_mcp"`: 16 passed, 2 skipped (M1), 1 xfailed (row 15).

- **Current set** (`requirements.txt`, every wheel hash-checked): mcp 1.30.0, the newest 1.x, which the upstream's `mcp[cli]>=1.6.0` allows. netguard's `server/discover` gets an error from the upstream, and go-sdk falls back to `initialize`. netguard logs `msg="upstream ready" server=upa tools=3 protocol=2025-11-25 era=stateful`. `tools/list` returns exactly the three tools, as `upa.<tool>`. Three clients each call `upa.send_command_and_get_output` with `show version`: a 2025-11-25 agent, a 2026-07-28 agent (`server/discover`, then `_meta` on every request) and python-sdk 2.2.0, whose stdio client initialises at 2025-11-25. Each gets the transcript unchanged. The device log shows netmiko's whole session: `terminal width 511`, `terminal length 0`, `show version`, `exit`. That is one `show version` per call.
- **Locked set** (the upstream's own `uv.lock`, hashes checked by `uv sync --locked`): mcp 1.6.0, which speaks only `2024-11-05`. The tests assert both of the following against the bare upstream, with no netguard in front. Its SDK's receive loop raises on a method it does not know, so after `server/discover` it answers nothing, not even `initialize`, and the process keeps running. `netguard serve` in front of it waits out the 30-second startup limit and exits 1 with `netguard: proxy: upstream upa: connect: context deadline exceeded`. That was the strict xfail `test_locked_upstream_initialises_behind_netguard`. go-sdk skips the probe when `ClientSessionOptions.ProtocolVersion` is set below 2026-07-28, but netguard passed none (`internal/proxy/proxy.go`). T0.39 fixed it ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)); see the next entry.
- The same code behind netguard, other SDK versions (by hand, not in CI):
  - mcp 1.6.0 to 1.9.3: the same failure.
  - 1.9.4: negotiates `2025-03-26`.
  - 1.10.0 to 1.23.0: `2025-06-18`.
  - 1.23.3 and 1.30.0: `2025-11-25`.
  - 2.x: `main.py` fails at import, because `mcp.server.fastmcp` became `MCPServer`. So the README's `uv run --with "mcp[cli]" ...` install, which resolves the newest mcp when run outside the project directory, fails today with or without netguard.
- ADR 0014 (a 2026 agent calling a tool whose stateful upstream sends `elicitation/create`) cannot happen here: upa's tools never elicit. `tests/conformance/era_pairs.py` covers that case against go-sdk v1.6.1.
- 2026-era half: `test_passthrough.py::test_upstream_negotiates_2026_07_28_stateless` asserts `protocol=2026-07-28 era=stateless` for netdev-ssh-mcp v1.6.6 (CI job `client-smoke`).
- CI, on the pull request (ubuntu-latest, linux/amd64):
  - job `tier2 upa/mcp-netmiko-server (2025 era)`: 7 passed, 1 xfailed; 45 s of tests, 1 min 38 s including the build and install ([run 35956218324](https://github.com/joshscott13/netguard/actions/runs/35956218324/job/107494992904)).
  - `client-smoke`, with the netdev-ssh-mcp era check: 16 passed, 2 skipped, 1 xfailed.
- Status after this run: the 2025-11-25 and 2026-07-28 eras negotiated against the named real servers, which is what M0 exit criterion 3 names, and row 2 was `passing` on that ground (maintainer decision 2026-09-23). The 2024-11-05 case (upa on its own lock) is neither named era, so it fell outside the criterion; it stayed a strict xfail, tracked as T0.39. T0.39 closed it; see the next entry.

**Row 2, 2026-09-24 (T0.39, T0.41): `passing`.** netguard at `51921ed` (`main`, after PR #77 and PR #79), built by `make build` with go1.26.8 and go-sdk v1.8.0. CI run [36050545450](https://github.com/joshscott13/netguard/actions/runs/36050545450) on the push to `main`, ubuntu-24.04, linux/amd64. That run is red only on the `STATUS.md is current` job (board sync, not a test); every test job is green.

- 2025 era and the locked case: job `tier2 upa/mcp-netmiko-server (2025 era)` ([job 107804699914](https://github.com/joshscott13/netguard/actions/runs/36050545450/job/107804699914)), `pytest integration -m "tier2 and upa_mcp_netmiko_server"`: 8 passed, none xfailed, in 25 s. Upstream: upa/mcp-netmiko-server at commit `96e8ff321cc839eeb525474736439ddc2ebc795c` (the checkout checks the id; the tests check `main.py`'s sha256), installed twice by `install.sh`. With mcp 1.30.0 (hash-pinned `requirements.txt`), netguard logs `protocol=2025-11-25 era=stateful`. With the upstream's own `uv.lock` (mcp 1.6.0, `uv sync --locked`), `test_locked_upstream_initialises_behind_netguard` passes as a plain test (its xfail marker is gone): `tools/list` returns the three `upa.<tool>` names, netguard logs `protocol=2024-11-05 era=stateful`, and exactly one `level=WARN` line says the upstream `did not answer server/discover within 5s`. The two direct cases, with no netguard in front, still pass: the locked upstream answers `initialize` with `2024-11-05`, and after `server/discover` it answers nothing and logs a pydantic `ValidationError`. So the upstream's defect is unchanged, and netguard is what handles it.
- 2026 era: job `tier2 client smoke (netdev-ssh-mcp)` ([job 107804699804](https://github.com/joshscott13/netguard/actions/runs/36050545450/job/107804699804)), `krisiasty/netdev-ssh-mcp` v1.6.6 linux_amd64 release binary (sha256 `256ab497…75621`): 16 passed, 2 skipped (M1), 1 xfailed (row 15), including `test_upstream_negotiates_2026_07_28_stateless`.
- Client-facing side: job `mcp-conformance` is green in the same run. Its upstreams are go-sdk fixtures (see the T0.19 entry), so it proves the agent side of the proxy, not either named upstream.
- Real servers the row rests on: krisiasty/netdev-ssh-mcp v1.6.6 (2026-07-28), and upa/mcp-netmiko-server `96e8ff3` with mcp 1.30.0 (2025-11-25) and with mcp 1.6.0 from its own `uv.lock` (2024-11-05). The go-sdk conformance fixtures, the fake SSH device and the by-hand SDK sweep in the T0.34 entry (mcp 1.9.4 to 1.23.0) support the row but prove none of it.
- Open follow-ups from the PR #77 and #79 reviews; neither changes row 2's status: T0.46 (a launcher's grandchild can outlive the restart; the CI cases start the upstream's Python directly, not through a launcher) and T0.47 (the era label after an initialize-only connect, which matters once M1 audits it).

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
