# M1-22: eos-mcp 1.3.0 runs in tier 2 behind fathomgate against a fake eAPI device; one profile finding

- **Task:** M1-22 — Tier 2 harness for eos-mcp run_command behind fathomgate, with a fake eAPI device
- **From → To:** test-engineer → upstream-server-scout (release-engineer also reviews the CI job)
- **State now:** in review
- **Branch / PR:** `test/eos-mcp-tier2` · PR link in the PR description (opened with this commit)
- **Date:** 2026-09-25

## Done

- `tests/fixtures/device/fake_eapi.py` (new): HTTPS `POST /command-api`, JSON-RPC `runCmds`, Basic auth with FAKE credentials, answers from `transcripts/eos/*.txt` (text) and `transcripts/eos/eapi/*.json` (json), eAPI's 1002 error shape for unknown commands. Logs every TCP accept before TLS (`connections.log`), every request's whole `cmds` list (`requests.log`) and every command (`commands.log`). Standard library server; the throwaway certificate comes from `cryptography` (already in the `integration` extra). Listens on `127.0.0.1:443`, because eos-mcp gives pyeapi no port.
- New FAKE transcripts: `show_ip_bgp_summary.txt`, `show_tech_support.txt`, `eapi/show_version.json`, `eapi/show_hostname.json` (synthetic; table in `tests/fixtures/device/README.md`).
- `tests/integration/upstreams/eos-mcp/` (new): `requirements.in/.txt` (eos-mcp 1.3.0 wheel, mcp 1.28.1 and pyeapi 1.0.4 as the upstream's `uv.lock` has them, every wheel hashed) and `install.sh` (prints `FATHOMGATE_EOS_MCP`).
- `tests/integration/conftest.py`: `eos_mcp_install` checks versions and the sha256 of every installed `eos_mcp/*.py` against commit `bffb893`; `fake_eapi` fixture; `eos_mcp_config` (FAKE `config.ini`); `owner_only_file` moved here from `test_policy_gate.py`.
- `tests/integration/test_eos_mcp.py` (new, markers `tier2`, `eos_mcp`), 10 cases: `--no-policy` smoke (17 tools, 2025-11-25 stateful, `show version` once), push_config `dry_run` default still sends `end`/`reload now` in the session call, `verify = true` not enforced; `--policy read-only.yaml`: `show version` and `show ip bgp summary` allow `reads-anywhere`, `reload` deny `no-exec`, `localhost` and `10.99.99.99` deny `default:unknown_target` with no TCP connection, `config_path` (three values, two tools) deny `default:bad_arguments`, push_config `["end","reload now"]` deny `no-exec` EXEC_ARBITRARY, `collect_tech_support` READ_CONFIG (allowed, and denied alongside `run_command show tech-support` under a policy denying READ_CONFIG). Every denial asserts the exact tool error and the decision line.
- `.github/workflows/ci.yaml`: job `tier2-eos-mcp` (name `tier2 eos-mcp (eAPI, --policy)`), ubuntu-latest, actions pinned by SHA, uv cache keyed on the requirements, `sysctl net.ipv4.ip_unprivileged_port_start=443`, `FATHOMGATE_TIER2_REQUIRED=1`.
- Docs: `tests/README.md`, `tests/fixtures/device/README.md` (what the fake cannot prove, for M1-28's cEOS items), `docs/testing/test-strategy.md`, a row 4 run note in `docs/testing/test-matrix.md` (status stays `planned`; M1-28 closes it).

## Look at this first

- `test_passthrough_verify_true_is_not_enforced`: on the real upstream, `verify = true` in eos-mcp's `config.ini` does not verify the device certificate. `eos_mcp/eapi.py` `get_node` passes `verify=` to `pyeapi.connect`; pyeapi 1.0.4 `connect` does not forward it, and `HttpsEapiConnection` builds `ssl._create_unverified_context()` when no context is given. `profiles/eos-mcp.yaml` hazards 1 and 2 (and brief 02 §1.5) tell operators to set `verify = true`; that advice protects nothing. Please correct the profile header and the brief, and consider reporting it upstream.

## Deliberately unfinished

- Row 4 is not marked `passing`: M1-28 runs the upa and eos-mcp halves together and records run ids.
- The fake's configure sessions are a sketch; the cEOS checks (lines after `end`, alias, `clock set`/`watch`/`terminal`, commit timer) are M1-28/M3, listed in the device README.
- `run_commands`, the batch tools and `daily_brief` are not exercised (not in the brief).

## Reproduce green

```sh
make build
export $(tests/integration/upstreams/eos-mcp/install.sh /tmp/eos-mcp)
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443   # Linux only
cd tests && FATHOMGATE_TIER2_REQUIRED=1 uv run --extra integration pytest integration -m "tier2 and eos_mcp" -v
```

Local (Windows 11, `FATHOMGATE_BIN=bin/fathomgate.exe`): 10 passed. With `--no-policy` substituted for the policy, the seven gate cases fail.

## Decisions made without an ADR

- Port 443 plus a CI sysctl rather than root or pyeapi's `http_local` transport (which ignores the hostname and is plain HTTP, so an unknown host would not be a real test).
- `cryptography` for the throwaway certificate: no committed key, no new dependency (asyncssh already pulls it).

## Questions for the receiver

- Should the profile keep recommending `verify = true` with a caveat, or recommend a local eAPI proxy or `ca_file` setup instead, given eos-mcp cannot pass a context?
