# M1-22: eos-mcp 1.3.0 runs in tier 2 behind fathomgate against a fake eAPI device; one profile finding

- **Task:** M1-22 — Tier 2 harness for eos-mcp run_command behind fathomgate, with a fake eAPI device
- **From → To:** test-engineer → upstream-server-scout (release-engineer also reviews the CI job)
- **State now:** in review
- **Branch / PR:** `test/eos-mcp-tier2` · [PR #182](https://github.com/fathomgate/fathomgate/pull/182)
- **Date:** 2026-09-25

## Done

- `tests/fixtures/device/fake_eapi.py` (new): HTTPS `POST /command-api`, JSON-RPC `runCmds`, Basic auth with FAKE credentials, answers from `transcripts/eos/*.txt` (text) and `transcripts/eos/eapi/*.json` (json), eAPI's 1002 error shape for unknown commands. Logs every TCP accept before TLS (`connections.log`), every request's whole `cmds` list (`requests.log`) and every command (`commands.log`). Standard library server; the throwaway certificate comes from `cryptography` (already in the `integration` extra). Listens on `127.0.0.1:443`, because eos-mcp gives pyeapi no port.
- New FAKE transcripts: `show_ip_bgp_summary.txt`, `show_tech_support.txt`, `eapi/show_version.json`, `eapi/show_hostname.json` (synthetic; table in `tests/fixtures/device/README.md`).
- `tests/integration/upstreams/eos-mcp/` (new): `requirements.in/.txt` (eos-mcp 1.3.0 wheel, mcp 1.28.1 and pyeapi 1.0.4 as the upstream's `uv.lock` has them, every artifact hashed; pyeapi 1.0.4 is an sdist, built with the setuptools hashed in `build-constraints.txt`, see round 2) and `install.sh` (prints `FATHOMGATE_EOS_MCP`).
- `tests/integration/conftest.py`: `eos_mcp_install` checks versions and the sha256 of every installed `eos_mcp/*.py` against commit `bffb893`; `fake_eapi` fixture; `eos_mcp_config` (FAKE `config.ini`); `owner_only_file` moved here from `test_policy_gate.py`.
- `tests/integration/test_eos_mcp.py` (new, markers `tier2`, `eos_mcp`), 10 cases: `--no-policy` smoke (17 tools, 2025-11-25 stateful, `show version` once), push_config `dry_run` default still sends `end`/`reload now` in the session call, `verify = true` not enforced; `--policy read-only.yaml`: `show version` and `show ip bgp summary` allow `reads-anywhere`, `reload` deny `no-exec`, `localhost` and `10.99.99.99` deny `default:unknown_target` (see round 2 for what the device log proves for each), `config_path` (three values, two tools) deny `default:bad_arguments`, push_config `["end","reload now"]` deny `no-exec` EXEC_ARBITRARY, `collect_tech_support` READ_CONFIG (allowed, and denied alongside `run_command show tech-support` under a policy denying READ_CONFIG). Every denial asserts the exact tool error and the decision line.
- `.github/workflows/ci.yaml`: job `tier2-eos-mcp` (name `tier2 eos-mcp (eAPI, --policy)`), ubuntu-latest, actions pinned by SHA, uv cache keyed on the requirements, `sysctl net.ipv4.ip_unprivileged_port_start=443`, `FATHOMGATE_TIER2_REQUIRED=1`.
- Docs: `tests/README.md`, `tests/fixtures/device/README.md` (what the fake cannot prove, for M1-28's cEOS items), `docs/testing/test-strategy.md`, a row 4 run note in `docs/testing/test-matrix.md` (status stays `planned`; M1-28 closes it).

## Round 2 (security review of PR #182: request changes, one medium)

- Merged `origin/main`; `STATUS.md` re-rendered.
- Medium, unhashed build backend: pyeapi 1.0.4 is on PyPI as an sdist only, and uv's isolated build pulled setuptools unhashed. New `tests/integration/upstreams/eos-mcp/build-constraints.in/.txt` (setuptools 84.0.0, hashed), passed by `install.sh` with `--build-constraints`. New `check-build-constraints.sh`, run first in the CI job: it builds pyeapi alone with no cache, once with the real constraints (must pass) and once with the hashes zeroed (must fail on a hash mismatch), so the CI's uv is shown to enforce them. Locally, uv 0.12.17 rejects the bad hash and, with no `--build-constraints`, installs the sdist with unhashed setuptools under `--require-hashes`, which is the gap. The CI comment, `tests/README.md` and the matrix note no longer say "every dependency hash-checked" of wheels alone.
- 3: `test_passthrough_unlisted_localhost_reaches_device` (new, `--no-policy`) is the control: `localhost` reaches the fake with the `[DEFAULT]` FAKE credentials and SNI `localhost`. The fake now also listens on `[::1]:443` (`--also-ipv6-loopback`), so `localhost` reaches it whichever address resolves first; if `localhost` resolves first to an address the fake could not bind, the control skips (fails under `FATHOMGATE_TIER2_REQUIRED=1`). The gated test's docstring now says the device log is evidence for `localhost` only; `10.99.99.99` rests on the tool error and the `forwarded=false` decision line. On this Windows host another program holds `[::1]:443` and `localhost` resolves to `::1` first, so the control skips here; it must run in CI.
- 4: `fake_eapi.py --host` refuses anything but a loopback address literal (exit 2), names included.
- 6: `show_tech_support.txt` row in the device README and the `collect_tech_support` test say M2 must add a FAKE secret so the case covers redaction.
- Verify finding folded in: `profiles/eos-mcp.yaml` hazards 1 and 2 and brief 02 §1.5 no longer present `verify = true` as a mitigation; they state that eos-mcp 1.3.0 passes `verify=` to `pyeapi.connect`, pyeapi 1.0.4 drops it (`client.py:394-461` never forwards it) and uses an unverified context, and `eos_mcp/eapi.py:13-27` patches `ssl._create_unverified_context` process-wide to `SECLEVEL=0` and TLS 1.0 minimum. `docs/security/threat-model.md`: new row "Upstream transport hazards accepted (eos-mcp, upstream ↔ device)", accepted for the upstream, mitigated by the inventory, the `default:unknown_target` deny and the refused `config_path`.

## Look at this first

- The profile header (hazards 1 and 2) and brief 02 §1.5 as corrected in round 2: please confirm the wording, as the profile's author.
- The draft upstream issue below: for the maintainer to approve before anyone files it.

### Draft issue for shigechika/eos-mcp (not filed; needs the maintainer's approval)

> **Title:** `verify = true` in config.ini is ignored: eAPI TLS certificates are never checked
>
> eos-mcp 1.3.0 reads a per-host `verify` key (`eos_mcp/config.py`, `get_creds`) and passes it to `pyeapi.connect(..., verify=verify)` in `eos_mcp/eapi.py` `get_node`. pyeapi 1.0.4's `connect()` does not use a `verify` keyword: it forwards only `context` (among the TLS settings) to `make_connection`, and `HttpsEapiConnection` builds `ssl._create_unverified_context()` whenever `context` is None. So the device certificate is never verified, whatever `verify` says. In addition, `eos_mcp/eapi.py` replaces `ssl._create_unverified_context` process-wide with a context at `SECLEVEL=0` and a TLS 1.0 minimum.
>
> Effect: anything that can answer on a configured device's name or address on port 443 receives the eAPI Basic-auth username and password, even with `verify = true`.
>
> Reproduce: point a host entry with `verify = true` at an HTTPS server with a self-signed certificate that answers `POST /command-api`; `run_command` succeeds and the server receives the credentials.
>
> Suggested fix: when `verify` is true, pass `context=ssl.create_default_context(cafile=<per-host ca_file, or the system store>)` to `pyeapi.connect` (optionally with a `ca_file` key in config.ini), and apply the SECLEVEL/TLS 1.0 relaxation only to a context built for hosts with `verify = false`, instead of patching `ssl._create_unverified_context` globally.

## Deliberately unfinished

- Row 4 is not marked `passing`: M1-28 runs the upa and eos-mcp halves together and records run ids.
- The fake's configure sessions are a sketch; the cEOS checks (lines after `end`, alias, `clock set`/`watch`/`terminal`, commit timer) are M1-28/M3, listed in the device README.
- `run_commands`, the batch tools and `daily_brief` are not exercised (not in the brief).

## Reproduce green

```sh
make build
tests/integration/upstreams/eos-mcp/check-build-constraints.sh /tmp/eos-mcp-bc
export $(tests/integration/upstreams/eos-mcp/install.sh /tmp/eos-mcp)
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443   # Linux only
cd tests && FATHOMGATE_TIER2_REQUIRED=1 uv run --extra integration pytest integration -m "tier2 and eos_mcp" -v
```

Local (Windows 11, `FATHOMGATE_BIN=bin/fathomgate.exe`), round 2: 10 passed, 1 skipped (the `localhost` control, `[::1]:443` held by another program here); round 1: 10 passed. With `--no-policy` substituted for the policy, the seven gate cases fail. CI: [run 36188295704](https://github.com/fathomgate/fathomgate/actions/runs/36188295704), job `tier2 eos-mcp (eAPI, --policy)` 10 passed, every job green.

## Decisions made without an ADR

- Port 443 plus a CI sysctl rather than root or pyeapi's `http_local` transport (which ignores the hostname and is plain HTTP, so an unknown host would not be a real test).
- `cryptography` for the throwaway certificate: no committed key, no new dependency (asyncssh already pulls it).

## Questions for the receiver

- Round 2 removed `verify = true` from the profile's advice. Is there an operator control worth recommending beyond fathomgate's inventory and a trusted network path, until an upstream fix lands?
