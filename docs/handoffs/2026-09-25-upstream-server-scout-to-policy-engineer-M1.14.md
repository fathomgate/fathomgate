# M1.14: netdev-ssh-mcp and eos-mcp profiles checked against their pinned source; upa added to the coverage test

- **Task:** M1.14, Audit the netdev-ssh-mcp and eos-mcp profiles against brief 02 and their pinned releases; add a profile-coverage test
- **From → To:** upstream-server-scout → policy-engineer (security-reviewer and go-reviewer also review)
- **State now:** in review. This PR does not edit `docs/milestones/`; move M1-14 on the board when you pick it up.
- **Branch / PR:** `feat/profile-coverage` · [PR #158](https://github.com/fathomgate/fathomgate/pull/158)
- **Date:** 2026-09-25

## Done

- **netdev-ssh-mcp, v1.7.1 `6fc6ab0`.** Every tool, class and parameter name matches. The header now cites file:line for all five tools (`main.go:84-145`, the input structs, and the command each one sends). No class changed.
- **eos-mcp, v1.3.0 `bffb893`** (PyPI 1.3.0, the newest tag; the profile had no pin before). All 17 tools and their parameter names match. Discrepancies fixed:
  1. `collect_tech_support` changed from `READ_OPERATIONAL` to `READ_CONFIG`. It sends `show tech-support` (`eapi.py:158-160`), and that output includes the running-config. The typed tool must not be looser than the same command through `run_command`, which PR #152 makes `READ_CONFIG`.
  2. The `run_command_batch` note said an empty selection runs on every device. That is wrong: it returns "No hosts resolved" (`server.py:296-298`). Only `daily_brief` does that, and only with both selectors omitted (`476-478`). The notes and profile-schema §2 are fixed.
  3. Brief 02 said `hostname` "must exist in config.ini". It does not: configparser's `fallback` also covers a missing section (`config.py:62-70`), so any host connects with the `[DEFAULT]` credentials. This is hazard 1 below.
- **Coverage test (exit criterion 1).** The `want` table in `internal/classify/profiles_repo_test.go` now has a `upa` row set, and `collect_tech_support` is `ReadConfig` there. `TestRepoProfiles` already fails on a missing tool, a wrong class or an extra tool (a count mismatch), so the three M1 upstreams are now covered. Mutation check: with `get_network_device_list` removed from the upa profile, the test fails with `upa: tool get_network_device_list missing` and `profile has 2 tools, catalog has 3`. The change to the Go file is data rows only.
- The brief 02 §1.1 and §1.5 updates, the §2(c) class table, profile-schema §6, and CHANGELOG (Added and Changed).

## Look at this first

- The `profiles/eos-mcp.yaml` header, "Hazards" 1 and 2, then `eos_mcp/config.py:62-70` and `server.py:22-30`:
  https://github.com/shigechika/eos-mcp/blob/bffb89377b3fa6b544b45b0cab44d5191cf8981a/eos_mcp/config.py

## Comma and newline (security note on PR #152)

| Upstream | Splits on `,` | Splits on newline | Evidence |
| --- | --- | --- | --- |
| netdev-ssh-mcp v1.7.1 | no | refuses it (control characters, U+2028, U+2029 and `;` are all refused) | `command_safety.go:76-84`; one `session.Output(cmd)`, `sshclient/client.go:102-107, 162` |
| eos-mcp v1.3.0 | no | no split. Each string is one eAPI `cmds` element; what EOS does with an embedded LF is uncertain | `eapi.py:94-104`; pyeapi 1.0.4 `EapiConnection.execute`/`request`, `eapilib.py:306-359, 596-634`. The `MULTILINE:` split in `Node.run_commands` is not on this path |
| upa `96e8ff3` | no | the device runs each line (netmiko writes the string to the channel) | `main.py:82-85` `conn.send_command(cmd)`; the M1-16 critical finding |

So `show version,reload` is one command on all three, and no device CLI here treats a comma as a separator. The device side was not tried (uncertain). It is already denied on `main` through all three free-form tools (`no-exec`: the comma fails the allow-list), and eos-mcp and upa `run_command`/`send_command_and_get_output` show the same result.

## Deliberately unfinished (specified for policy-engineer)

- **Go reload cases**, to be added to `TestRepoProfiles` as table rows (`profile, tool, args, want class`), or confirmed as already covered by PR #152's `security_test.go`:
  - `upa` `send_command_and_get_output` `{name: lab-leaf-01, command: reload}` → `EXEC_ARBITRARY`; `{…, command: "show version"}` → `READ_OPERATIONAL`
  - `netdev-ssh-mcp` `run_show_command` `{host: lab-leaf-01, command: reload}` → `EXEC_ARBITRARY`
  - `show version,reload` through all three free-form tools → `EXEC_ARBITRARY`
  - `eos-mcp` `collect_tech_support` `{hostname: lab-leaf-01}` → `READ_CONFIG`
- **Schema proposals (each needs an ADR):** (a) `forbidden_params` or `strip_params` per tool, for eos-mcp `config_path`; (b) a per-argument pattern, for netdev `run_ping`/`run_traceroute` leading `-` (T0.53). The profile records the decision: both stay `READ_OPERATIONAL`, because the verb is fixed and the worst case is an extra ping option.
- There is no `docs/upstreams/*.md`. The hazards live in the profile headers and in brief 02, as they do for upa.

## Hazards for security-reviewer (eos-mcp v1.3.0, all [src])

1. Any `hostname` gets the `[DEFAULT]` eAPI credentials, over HTTPS with `verify=False` by default and a process-wide TLS context lowered to `SECLEVEL=0` and TLS 1.0 (`eapi.py:17-27`). An agent can send the fleet's credentials to a host it names. Behind fathomgate, `default:unknown_target` is the control (checked: `get_version hostname=evil.example` gives `deny`).
2. `config_path` on every tool reads a file the agent chooses. A parse error echoes that file's first line (reproduced locally with configparser), and the file supplies the credentials for that call.
3. `push_config` `dry_run=True` is not a sandbox. `config_lines` are unfiltered inside one eAPI call, so `end` plus later lines may run outside the session (uncertain on a device). `session_name` and `commit_timer` are interpolated unchecked. For network-safety-engineer, the upstream hooks are `dry_run` (default true), `commit_timer` (default 300 s), `confirm_config_session` and `abort_config_session`.
4. `daily_brief` with no selector runs on the whole fleet while fathomgate sees zero targets.

## Reproduce green

```sh
go build -o bin/fathomgate ./cmd/fathomgate && go vet ./... && go test ./...
bin/fathomgate policy test policies/examples/lab-open.test.yaml policies/examples/prod-approval.test.yaml policies/examples/read-only.test.yaml   # 25/25
E="bin/fathomgate policy eval --inventory inventory.example.yaml --server eos-mcp --profile profiles/eos-mcp.yaml"
$E --policy policies/examples/read-only.yaml --tool run_command --arg hostname=lab-leaf-01 --arg "command=show version"   # allow READ_OPERATIONAL
$E --policy policies/examples/read-only.yaml --tool run_command --arg hostname=lab-leaf-01 --arg command=reload          # deny EXEC_ARBITRARY no-exec
$E --policy policies/examples/read-only.yaml --tool collect_tech_support --arg hostname=lab-leaf-01                      # allow READ_CONFIG
$E --policy policies/examples/prod-approval.yaml --tool push_config --arg hostname=core-rtr-01 --arg "config_lines=interface Ethernet1"   # hold, dry_run diff timed_rollback
```

## Decisions made without an ADR

- The `collect_tech_support` class raise, which is a profile decision. Proposed test-matrix row (test-engineer): "eos-mcp `collect_tech_support` on a lab device | 1, 2 | eos-mcp v1.3.0 (`pip install eos-mcp==1.3.0`) | Allowed as `READ_CONFIG`, `redact` | M1". Fixture error shapes are plain text results, not `isError`: `Error (<host>): <exception>`, `No hosts resolved (check hostnames/tags).`, and `Error: Config file not found: <path>`.

## Questions for the receiver

- Do you want `forbidden_params` (hazard 2) as an M1 task, or an M2 one next to the alias cross-check from M1.13?
