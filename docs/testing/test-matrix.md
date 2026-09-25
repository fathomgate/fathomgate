# Test matrix

The 22 cases from [PLAN.md](../PLAN.md#test-matrix). Every case names the real upstream server it is validated against. Tier definitions are in [test-strategy.md](test-strategy.md). Status moves from `planned` to `passing` when the case runs green in CI; a case that is skipped for a licence reason is `skipped` with the reason.

| # | Case | Tier | Upstream server | Expected | Milestone | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `tools/list` passes through with server prefix | 2 | netdev-ssh-mcp | Tools appear as `netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config`, and so on (the prefix is the profile `server` key) | M0 | passing (client-smoke CI, netdev-ssh-mcp v1.7.1 since T0.51; Claude Code 2.1.236 and Claude Desktop 2.7032.0 by hand with v1.6.6, 2026-09-23; see [run notes](#run-notes)) |
| 2 | Dual-era handshake | 2 | netdev-ssh-mcp (go-sdk, 2026 era); upa/mcp-netmiko-server (FastMCP, 2025 era) | Both upstreams initialise; conformance suite green on the client-facing side | M0 | passing: netdev-ssh-mcp v1.7.1 initialises behind fathomgate at 2026-07-28 (tier 2 CI run 36088442110, T0.51); upa/mcp-netmiko-server `96e8ff3` (tier 2 CI on `main` at `51921ed`, 2026-09-24) initialises at 2025-11-25 with mcp 1.30.0, for a 2025-11-25 agent and a 2026-07-28 agent, and at 2024-11-05 on its own `uv.lock` (mcp 1.6.0) after fathomgate restarts it once and connects with `initialize` only ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)); `mcp-conformance` green. See [run notes](#run-notes) |
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
| 15 | Secret redaction on `get_config` | 1, 2 | netdev-ssh-mcp `get_config`; junos-mcp-server `get_junos_config` | Every fixture secret replaced with a fathomgate redacted token (`<redacted:hmac:…>`), with the upstream's own obfuscation off (netdev-ssh-mcp `--no-obfuscate`); the upstream's `[h:…]` tokens are not redacted tokens and do not count; `redactions` count and pattern ids logged | M2 | planned |
| 16 | Tool description rug-pull | 2 | Any server with a modified description | Server quarantined; `quarantine` audit event with pinned and observed hashes | M2 | planned |
| 17 | Upstream elicitation origin | 2 | junos-mcp-server (streamable-http) | Prompt re-labelled with the server name before reaching the client | M3 | planned |
| 18 | Meta-tool classification | 1 | Meraki official `execute_api` fixture | Class from the `capability_id` table; `class_source: capability_table` | M1 | planned |
| 19 | Audit tamper | 1 | none | `fathomgate audit verify` fails on an edited line and names it; exit status 1 | M4 | planned |
| 20 | Timed rollback fires | 3 | eos-mcp on cEOS | Unconfirmed configure session reverts at the timer; device state asserted over scrapli | M3 | planned |
| 21 | Watchdog rollback | 3 | netdev-ssh-mcp on NX-OS image | Checkpoint restored at the watchdog deadline | M5 | skipped until an NX-OS image is licensed on the runner |
| 22 | PATH-stripped launcher | 2 | Claude Desktop-style config with absolute binary path and empty `PATH`; netdev-ssh-mcp v1.7.1 behind fathomgate | Proxy starts and serves `tools/list`; no ENOENT | M0 | passing (client-smoke CI, netdev-ssh-mcp v1.7.1 since T0.51; Claude Code 2.1.236 and Claude Desktop 2.7032.0 by hand with v1.6.6, 2026-09-23; see [run notes](#run-notes)) |

## Run notes

One entry per run that changed a row's status or added evidence for it. A row becomes `passing` only when its case runs green in CI against the named real server; rows 1 and 22 also need the manual real-client check in [install.md](../install.md#check-it-works) before M0 exit criterion 2 can be ticked.
- **2026-09-23, rows 1 and 22 passing, M0 exit criterion 2 met.** Upstream `krisiasty/netdev-ssh-mcp` v1.6.6 (`go install`), fathomgate from `main`, fake EOS device (`tests/fixtures/device/fake_ssh.py`, port 22022). The maintainer asked each client, in plain words, for `show version` on `127.0.0.1` port 22022 device type `eos`; each answer contained `Serial number: FAKE0000SN01`, and the device's `commands.log` recorded exactly one `show version` per client (two lines in total).
  - **Claude Code 2.1.236**, `claude mcp add` with absolute paths, run from a terminal.
  - **Claude Desktop 2.7032.0**, `claude_desktop_config.json` with absolute paths, started from the Dock (the PATH-stripped launch, row 22).
  - CI job `tier2 client smoke (netdev-ssh-mcp)` green on `main` at `b4c3b4e`.
  - Cursor was not installed on the test Mac; Claude Desktop is the second client. Cursor stays documented in `docs/install.md` but unexercised.


**Rows 1 and 22, 2026-09-23 (T0.5).** Upstream: krisiasty/netdev-ssh-mcp v1.6.6, both the release binary `netdev-ssh-mcp_1.6.6_darwin_arm64` (sha256 `42b4f18a…b4493`, commit `be3e3634`) and a `go install …@v1.6.6` build. Device: `tests/fixtures/device/fake_ssh.py` (EOS persona, exec channel). fathomgate at `20781c7`, macOS arm64. `uv run --extra integration pytest integration -m tier2`: 11 passed, 2 skipped (the M1 cases).

- Row 1: `tests/integration/test_passthrough.py`. `tools/list` returns exactly the five upstream tools as `netdev-ssh-mcp.<tool>`, matching `profiles/netdev-ssh-mcp.yaml`. A read-only `tools/call` (`run_show_command`, `show version`) reaches the fake device once and returns the transcript unchanged. The upstream's own refusal of `reload` comes back as `isError` and nothing reaches the device. In M0 that is not a `deny`: fathomgate decides nothing yet. Client: python-sdk `mcp` 2.2.0.
- Row 22: `tests/integration/test_launcher_path.py`. With absolute paths, `PATH=""` and a fully empty environment (`env -i`), fathomgate serves `tools/list` and a read call. Every broken form fails fast with exit 1 and the cause on stderr, with no hang (under 1 s each): a bare `--upstream` name gives `executable file not found in $PATH`; a wrapper that looks up the server on `PATH` gives the upstream's `not found` line and then `connection closed: calling "initialize"`; netdev-ssh-mcp with no `HOME` and no `SSH_KNOWN_HOSTS` exits at startup. The `--upstream-env PATH=…` fix is tested.
- Real client: Claude Code 2.1.236 in print mode, with `--mcp-config --strict-mcp-config` and `"env": {"PATH": ""}`, reported the server `connected` and listed `mcp__netdev__netdev-ssh-mcp_run_show_command` and the other four tools (Claude Code turns the `.` into `_`). The model turn did not run, because the CLI had no working login in the test session, so no `tools/call` went through Claude Code. Cursor was not run, because it cannot be driven headless.
- CI: the `client-smoke` job ran the same suite green on the pull request, against the linux_amd64 release binary (sha256 `256ab497…75621`): [run 35947953383](https://github.com/fathomgate/fathomgate/actions/runs/35947953383/job/107470027880).
- To be `passing`: `client-smoke` green on `main`. To tick exit criterion 2: a person does the install.md check in Claude Code and in Cursor.

**Rows 1 and 15, 2026-09-23 (T0.26).** Upstream: krisiasty/netdev-ssh-mcp v1.6.6, a `go install …@v1.6.6` build (go1.27.1). Device: the fake SSH device with a new `show running-config` transcript: a real public Arista vEOS EOS-4.16.6M sample from HPE documentation, with its two SNMP communities and two type-5 hashes replaced by FAKE values (provenance in `tests/fixtures/device/README.md`). fathomgate at `2459c3a` plus this change, macOS arm64. `uv run --extra integration pytest integration -m tier2`: 13 passed, 2 skipped (the M1 cases), 1 xfailed (the row 15 case).

- Row 1: a read-config call through fathomgate. The upstream refuses `show run…` in `run_show_command` and points to `get_config`, so the test calls `netdev-ssh-mcp.get_config` (`device_type: eos`, `config_type: running`). The device receives one `show running-config | no-more`. The fake device now drops a trailing `| no-more` when it looks up a transcript.
- The upstream replaces secrets itself by default (`internal/netdev/obfuscate.go`): each value becomes `[h:<first 6 bytes of sha256, hex>]`. The test pins that: the agent gets the transcript with exactly four lines changed, and each one carries that hash. The hash has no key, so a guessable value such as the sample's original `public` can be recovered with a dictionary. It is not fathomgate's redaction and does not count toward row 15.
- With the upstream's `--no-obfuscate` (passed after `--`), the agent gets all four FAKE credentials unchanged. That is the M0 fact, and the test asserts it on purpose: `fathomgate serve` forwards results as they are.
- Row 15 (tier 1): the same text, with rule annotations, is the redaction fixture `tests/fixtures/configs/eos-4.16.txt`. `make fixtures-check` shows the redactor catches all four in EOS-4.16 syntax (`cisco-snmp-community` 2, `cisco-password-type` 2), with no hits anywhere else in the config. The original published values give the same four hits.
- Row 15 (tier 2): `test_running_config_redacted_by_fathomgate` is a strict xfail until the redactor runs at the response serialiser (ROADMAP M2). When it runs there, the case XPASSes, strict mode fails it, and `test_running_config_secrets_reach_agent_in_m0` fails with it. Flip both in that PR. Row 15 stays `planned`.

**Row 2, 2026-09-23 (T0.19).** Upstreams: go-sdk's conformance everything-server at v1.8.0 (the `go.mod` version; negotiates `2026-07-28` with fathomgate) and at v1.6.1 (the last release without `2026-07-28`; negotiates `2025-11-25`, logged as `upstream ready ... protocol=2025-11-25 era=stateful`). Suite `@modelcontextprotocol/conformance` 0.2.0-alpha.11. fathomgate at `b4c3b4e` (main, with T0.28 and T0.23) plus this change, macOS arm64. `make conformance PYTHON=python3`: every leg green against its baseline.

- 2025 agent x 2025 upstream (`fathomgate-up2025`, `--requirements 2025-11-25`): 14 of 30 scored scenarios clean, 50 scored checks passing, 16 baseline entries. `tools-call-elicitation` and `elicitation-sep1034-defaults` pass: the upstream's `elicitation/create` reaches the agent and the answer goes back. They stay baselined on the `fathomgate` leg, where the upstream is on `2026-07-28`. `elicitation-sep1330-enums` fails because go-sdk v1.8.0 (fathomgate's upstream client) refuses the fixture's `titledMulti` schema before fathomgate sees it, and fathomgate's allow-list would refuse it next (profile-schema section 8.4).
- 2026 agent x 2025 upstream (`fathomgate-up2025`, `--requirements 2026-07-28`): 12 of 37 scored scenarios clean, 65 scored checks passing, 42 baseline entries: 12 HTTP-transport checks (as on the control leg), 17 fathomgate decisions (as on the `fathomgate` leg), 13 checks that call 2026-era tools this upstream does not have. Listing, calls, content types, errors and progress cross the era boundary.
- `era_pairs.py`: for a 2025 agent the prompt arrives as `[from conf] <message>` and the accepted answer completes the tool; for a 2026 agent the call ends with `isError` and the exact ADR 0014 refusal, with no prompt shown. Both cells fail against the v1.8.0 fixture, so the check needs the 2025 upstream to pass.
- The existing legs are unchanged: `fathomgate` 12 of 30 (2025) and 18 of 37 (2026) scored scenarios clean, with 18 and 34 entries.
- Not validated: both upstreams are go-sdk fixtures. To be `passing`: netdev-ssh-mcp (go-sdk, 2026 era) and upa/mcp-netmiko-server (FastMCP, 2025 era) initialise behind fathomgate in tier 2 CI. Met since T0.34; see the T0.39, T0.41 entry.

**Row 2, 2026-09-24 (T0.34).** Upstream: upa/mcp-netmiko-server at commit `96e8ff321cc839eeb525474736439ddc2ebc795c` (2025-05-30; the project has no releases). The server is one file, `main.py`, sha256 `07e55298409e91dea62e2f245fad37be75e71a0dd8df9027f97ba0c7cca7babb`: FastMCP from the Python SDK, over stdio. `tests/integration/upstreams/upa-mcp-netmiko-server/install.sh` fetches that commit and builds two Python 3.13 environments, described in the bullets below. Device: the fake SSH device's new interactive shell, driven by netmiko 4.5.0 as `arista_eos`. fathomgate at `279d3b2` (main) plus this change, on macOS arm64. Clients: raw JSON-RPC in each era, and python-sdk `mcp` 2.2.0. `pytest integration -m "tier2 and upa_mcp_netmiko_server"`: 7 passed, 1 xfailed (strict), in about 40 s. `-m "tier2 and netdev_ssh_mcp"`: 16 passed, 2 skipped (M1), 1 xfailed (row 15).

- **Current set** (`requirements.txt`, every wheel hash-checked): mcp 1.30.0, the newest 1.x, which the upstream's `mcp[cli]>=1.6.0` allows. fathomgate's `server/discover` gets an error from the upstream, and go-sdk falls back to `initialize`. fathomgate logs `msg="upstream ready" server=upa tools=3 protocol=2025-11-25 era=stateful`. `tools/list` returns exactly the three tools, as `upa.<tool>`. Three clients each call `upa.send_command_and_get_output` with `show version`: a 2025-11-25 agent, a 2026-07-28 agent (`server/discover`, then `_meta` on every request) and python-sdk 2.2.0, whose stdio client initialises at 2025-11-25. Each gets the transcript unchanged. The device log shows netmiko's whole session: `terminal width 511`, `terminal length 0`, `show version`, `exit`. That is one `show version` per call.
- **Locked set** (the upstream's own `uv.lock`, hashes checked by `uv sync --locked`): mcp 1.6.0, which speaks only `2024-11-05`. The tests assert both of the following against the bare upstream, with no fathomgate in front. Its SDK's receive loop raises on a method it does not know, so after `server/discover` it answers nothing, not even `initialize`, and the process keeps running. `fathomgate serve` in front of it waits out the 30-second startup limit and exits 1 with `fathomgate: proxy: upstream upa: connect: context deadline exceeded`. That was the strict xfail `test_locked_upstream_initialises_behind_fathomgate`. go-sdk skips the probe when `ClientSessionOptions.ProtocolVersion` is set below 2026-07-28, but fathomgate passed none (`internal/proxy/proxy.go`). T0.39 fixed it ([ADR 0018](../adr/0018-bound-server-discover-then-initialize-only.md)); see the next entry.
- The same code behind fathomgate, other SDK versions (by hand, not in CI):
  - mcp 1.6.0 to 1.9.3: the same failure.
  - 1.9.4: negotiates `2025-03-26`.
  - 1.10.0 to 1.23.0: `2025-06-18`.
  - 1.23.3 and 1.30.0: `2025-11-25`.
  - 2.x: `main.py` fails at import, because `mcp.server.fastmcp` became `MCPServer`. So the README's `uv run --with "mcp[cli]" ...` install, which resolves the newest mcp when run outside the project directory, fails today with or without fathomgate.
- ADR 0014 (a 2026 agent calling a tool whose stateful upstream sends `elicitation/create`) cannot happen here: upa's tools never elicit. `tests/conformance/era_pairs.py` covers that case against go-sdk v1.6.1.
- 2026-era half: `test_passthrough.py::test_upstream_negotiates_2026_07_28_stateless` asserts `protocol=2026-07-28 era=stateless` for netdev-ssh-mcp v1.6.6 (CI job `client-smoke`).
- CI, on the pull request (ubuntu-latest, linux/amd64):
  - job `tier2 upa/mcp-netmiko-server (2025 era)`: 7 passed, 1 xfailed; 45 s of tests, 1 min 38 s including the build and install ([run 35956218324](https://github.com/fathomgate/fathomgate/actions/runs/35956218324/job/107494992904)).
  - `client-smoke`, with the netdev-ssh-mcp era check: 16 passed, 2 skipped, 1 xfailed.
- Status after this run: the 2025-11-25 and 2026-07-28 eras negotiated against the named real servers, which is what M0 exit criterion 3 names, and row 2 was `passing` on that ground (maintainer decision 2026-09-23). The 2024-11-05 case (upa on its own lock) is neither named era, so it fell outside the criterion; it stayed a strict xfail, tracked as T0.39. T0.39 closed it; see the next entry.

**Row 2, 2026-09-24 (T0.39, T0.41): `passing`.** fathomgate at `51921ed` (`main`, after PR #77 and PR #79), built by `make build` with go1.26.8 and go-sdk v1.8.0. CI run [36050545450](https://github.com/fathomgate/fathomgate/actions/runs/36050545450) on the push to `main`, ubuntu-24.04, linux/amd64. That run is red only on the `STATUS.md is current` job (board sync, not a test); every test job is green.

- 2025 era and the locked case: job `tier2 upa/mcp-netmiko-server (2025 era)` ([job 107804699914](https://github.com/fathomgate/fathomgate/actions/runs/36050545450/job/107804699914)), `pytest integration -m "tier2 and upa_mcp_netmiko_server"`: 8 passed, none xfailed, in 25 s. Upstream: upa/mcp-netmiko-server at commit `96e8ff321cc839eeb525474736439ddc2ebc795c` (the checkout checks the id; the tests check `main.py`'s sha256), installed twice by `install.sh`. With mcp 1.30.0 (hash-pinned `requirements.txt`), fathomgate logs `protocol=2025-11-25 era=stateful`. With the upstream's own `uv.lock` (mcp 1.6.0, `uv sync --locked`), `test_locked_upstream_initialises_behind_fathomgate` passes as a plain test (its xfail marker is gone): `tools/list` returns the three `upa.<tool>` names, fathomgate logs `protocol=2024-11-05 era=stateful`, and exactly one `level=WARN` line says the upstream `did not answer server/discover within 5s`. The two direct cases, with no fathomgate in front, still pass: the locked upstream answers `initialize` with `2024-11-05`, and after `server/discover` it answers nothing and logs a pydantic `ValidationError`. So the upstream's defect is unchanged, and fathomgate is what handles it.
- 2026 era: job `tier2 client smoke (netdev-ssh-mcp)` ([job 107804699804](https://github.com/fathomgate/fathomgate/actions/runs/36050545450/job/107804699804)), `krisiasty/netdev-ssh-mcp` v1.6.6 linux_amd64 release binary (sha256 `256ab497…75621`): 16 passed, 2 skipped (M1), 1 xfailed (row 15), including `test_upstream_negotiates_2026_07_28_stateless`.
- Client-facing side: job `mcp-conformance` is green in the same run. Its upstreams are go-sdk fixtures (see the T0.19 entry), so it proves the agent side of the proxy, not either named upstream.
- Real servers the row rests on: krisiasty/netdev-ssh-mcp v1.6.6 (2026-07-28), and upa/mcp-netmiko-server `96e8ff3` with mcp 1.30.0 (2025-11-25) and with mcp 1.6.0 from its own `uv.lock` (2024-11-05). The go-sdk conformance fixtures, the fake SSH device and the by-hand SDK sweep in the T0.34 entry (mcp 1.9.4 to 1.23.0) support the row but prove none of it.
- Open follow-ups from the PR #77 and #79 reviews; neither changes row 2's status: T0.46 (a launcher's grandchild can outlive the restart; the CI cases start the upstream's Python directly, not through a launcher) and T0.47 (the era label after an initialize-only connect, which matters once M1 audits it).

**Rows 1, 2, 15 and 22, 2026-09-25 (T0.51): netdev-ssh-mcp v1.6.6 to v1.7.1.** Upstream: krisiasty/netdev-ssh-mcp v1.7.1, tag commit `6fc6ab0aed1e84b8dd71b1bf1ad39cd909146623`. It fixes [GHSA-8g43-jrf3-q9vq](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-8g43-jrf3-q9vq) (v1.7.0: keyed obfuscation tokens, the T0.29 report) and [GHSA-h47r-329w-6p9h](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-h47r-329w-6p9h) (v1.7.1: command injection). The tool names, parameters and go-sdk v1.8.0 are unchanged; the source reading is in `profiles/netdev-ssh-mcp.yaml`. [PR #108](https://github.com/fathomgate/fathomgate/pull/108), fathomgate at `d40bb64`.

- CI: job `tier2 client smoke (netdev-ssh-mcp)` ([job 107925401855](https://github.com/fathomgate/fathomgate/actions/runs/36088442110/job/107925401855)), linux_amd64 release binary (sha256 `f90795b4…0c9e7`, from the release's `checksums.txt`, `sha256sum -c` OK). `-m "tier2 and netdev_ssh_mcp"`: 23 passed, 2 skipped (M1), 1 xfailed (row 15). Every other job in [run 36088442110](https://github.com/fathomgate/fathomgate/actions/runs/36088442110) is green. The first push, [run 36087378002](https://github.com/fathomgate/fathomgate/actions/runs/36087378002) at `3a49077`, had the same counts, before the review round tightened the assertions.
- By hand: Windows 11 amd64, `netdev-ssh-mcp_1.7.1_windows_amd64.exe` (sha256 `281ead1c…a7d7`, `go version -m` gives v1.7.1). 14 passed, 1 xfailed, and 11 skipped: the nine POSIX-only row 22 cases and the two M1 cases. Negative control: the same suite against v1.6.6 fails the eight new or changed cases below and passes the rest.
- Row 1: unchanged. The five prefixed tools, `show version` once on the device, and the upstream's refusal of `reload` as `isError` with nothing sent. New in `test_passthrough.py`:
  - `get_config` with a FAKE key file (`--upstream-env OBFUSCATION_KEY_FILE=…`): exactly four lines change, each to the upstream's HMAC token computed from the key.
  - With no key: four distinct `[h:…]` tokens, none of them the v1.6.6 unkeyed hash, and a second content block holding the upstream's per-run-key notice. fathomgate forwards it in M0. The upstream's `instructions` do not reach the agent: fathomgate does not relay them.
  - `test_upstream_refuses_command_injection`: LF, CRLF, `;`, `| redirect`, `| tee` and `>` each come back `isError` with the upstream's own refusal text, and the fake device logs nothing. This is the upstream's check, not a `deny`.
- Row 2: `test_upstream_negotiates_2026_07_28_stateless` passes against v1.7.1 in the same job.
- Row 22: all nine launcher cases pass against v1.7.1 on Linux. The by-hand real-client check (Claude Code, Claude Desktop) was done with v1.6.6 on 2026-09-23 and was not repeated; nothing on the launch path changed between the tags.
- Row 15: re-checked, and it stays `planned`. v1.7.x tokens are keyed, but under the upstream's key, and they are not fathomgate's `<redacted:hmac:…>`. The row's case runs with `--no-obfuscate`, so the upstream's tokens cannot mask a gap in fathomgate's redactor. The Expected cell now says so. With its trailing annotations stripped, the upstream's v1.7.1 obfuscator leaves 0 of the corpus's 71 secrets in clear (v1.6.6: 20 of 71, the T0.29 totals). Row 15 is about fathomgate, so this does not count toward it.
- Status: rows 1, 2 and 22 stay `passing`, now on v1.7.1, on run 36088442110 at `d40bb64` (the commit after it changes docs only).

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
