# Fathomgate Python companion

Everything a contributor without a Go toolchain needs: a linter for policy
files, the redaction fixture corpus, and the tier 2 integration tests that run
`fathomgate serve` in front of real upstream MCP servers.

```
tests/
  pyproject.toml        uv-friendly project: pytest, pyyaml, mcp
  policy_lint/          validate policy YAML against the DSL schema (python -m policy_lint)
  unit/                 tier 1: no network
  integration/          tier 2: spawn `fathomgate serve` + real MCP server + fake device
    upstreams/          pinned install recipes for upstreams without a release binary
  fixtures/configs/     sanitised running-configs with annotated FAKE secrets
  fixtures/device/      fake SSH device (asyncssh), fake eAPI device (HTTPS), canned transcripts
  conformance/          official MCP conformance suite vs fathomgate serve --listen: shim.py, era_pairs.py, baselines (make conformance)
```

## Running

```sh
cd tests
uv run --extra dev pytest unit -q            # tier 1
uv run python -m policy_lint ../policies/examples/prod-approval.yaml
# tier 2: needs bin/fathomgate (make build) and netdev-ssh-mcp v1.7.1, either the
# release binary or `go install github.com/krisiasty/netdev-ssh-mcp@v1.7.1`
FATHOMGATE_UPSTREAM=/abs/path/to/netdev-ssh-mcp uv run --extra integration pytest integration -m "tier2 and netdev_ssh_mcp" -v
# tier 2 against upa/mcp-netmiko-server: install.sh (git, uv) prints the three
# FATHOMGATE_UPA_* variables the tests read
export $(integration/upstreams/upa-mcp-netmiko-server/install.sh /tmp/upa)
uv run --extra integration pytest integration -m "tier2 and upa_mcp_netmiko_server" -v
# tier 2 against shigechika/eos-mcp 1.3.0: install.sh (uv) prints
# FATHOMGATE_EOS_MCP; the fake eAPI device needs 127.0.0.1:443 (on Linux:
# sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443)
export $(integration/upstreams/eos-mcp/install.sh /tmp/eos-mcp)
uv run --extra integration pytest integration -m "tier2 and eos_mcp" -v
```

Each upstream's cases skip when its variables are unset, so any one set runs
alone; `-m tier2` runs them all.

Policy *behaviour* is tested by the Go binary, not by Python:
`fathomgate policy test policies/examples/prod-approval.test.yaml` (or
`make policy-test` from the repo root). `policy_lint` only checks shape.

## The three tiers

| Tier | What is real | Runs where | Marker |
| --- | --- | --- | --- |
| 1 | Nothing. Synthetic `tools/call` requests, YAML files, fixture configs | every commit, `go test` + `pytest unit` | `tier1` |
| 2 | The upstream MCP server (tool schemas, transport, error shapes) in a container; a fake SSH device returns canned output | every pull request | `tier2` |
| 3 | Everything: containerlab topology with cEOS and SR Linux, real commits and rollbacks | nightly on a self-hosted runner (`.github/workflows/nightly-clab.yaml`) | `tier3` |

Every tier 2 and 3 case names the real server it is validated against
(see the test matrix in `docs/PLAN.md`), so nothing is tested only against
a mock.

## Status

- Tier 1: live (`unit/`, plus the Go suites).
- Tier 2: live for netdev-ssh-mcp v1.7.1 (CI job `client-smoke`, no Docker).
  - `integration/test_passthrough.py` covers matrix row 1: prefixed
    `tools/list`, and read-only `show version` and `get_config` calls through
    to the fake device. The row 15 `get_config` redaction case is a strict
    xfail until M2.
  - The same file covers the upstream's own keyed `[h:...]` tokens, with a
    FAKE key file and with its per-run random key, the fix for
    [GHSA-8g43-jrf3-q9vq](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-8g43-jrf3-q9vq).
  - It also covers the upstream's refusal of injected commands, the fix for
    [GHSA-h47r-329w-6p9h](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-h47r-329w-6p9h).
  - `integration/test_launcher_path.py` covers row 22 (the PATH-stripped
    launcher).
  - `integration/test_http_listener.py` covers row 23: `fathomgate serve
    --listen 127.0.0.1:0` with a FAKE bearer token (owner-only file, or
    `FATHOMGATE_LISTEN_TOKEN`), a python-sdk client over Streamable HTTP in
    both eras on both `listening` URLs, and raw-HTTP checks of the 401 and
    403 refusals, including a `tools/call` without a valid token that must
    reach no device. It stops Fathomgate as an operator does (SIGINT, or
    CTRL_BREAK_EVENT on Windows) and checks that the token never reached
    its stderr. It runs on Windows too; on a host with no IPv6 loopback
    the `[::1]` half skips locally and fails in CI.
  - `integration/test_policy_gate.py` covers matrix rows 3 and 6 through
    `fathomgate serve --policy` with the embedded profiles and an inventory
    listing only `127.0.0.1` (M1-28): `show ip bgp summary` allowed by
    `reads-anywhere` and run once, and `reload` denied by `no-exec`, under
    read-only.yaml and prod-approval.yaml; `localhost` and `10.99.99.99`
    denied by `default:unknown_target` for READ_OPERATIONAL, READ_CONFIG,
    EXEC_ARBITRARY and LOCAL_ADMIN under both and under a policy with
    `unknown_target` unset whose rules allow every class (ADR 0032). Each
    decision is asserted as the exact tool error and as the `decision` line
    on stderr; a `--no-policy` control shows `localhost` does reach the
    device when nothing denies it.
  - The two audit-event cases in `test_passthrough.py` stay skipped until
    `--audit` lands in M4.
  - Without `FATHOMGATE_UPSTREAM` the tier 2 tests skip; CI sets
    `FATHOMGATE_TIER2_REQUIRED=1` so they cannot skip there.
- Tier 2: live for upa/mcp-netmiko-server at commit `96e8ff3` (CI job
  `tier2-upa`, no Docker). `integration/test_upa_netmiko.py` covers the
  2025-era half of matrix row 2. With mcp 1.30.0 (hash-pinned
  `integration/upstreams/upa-mcp-netmiko-server/requirements.txt`), fathomgate
  negotiates 2025-11-25 stateful with it, lists `upa.<tool>`, and a 2025 and
  a 2026 agent each run `show version` once on the fake device through
  netmiko. With the upstream's own `uv.lock` (mcp 1.6.0), which never
  answers `server/discover`, fathomgate restarts it once and connects with
  `initialize` only, at 2024-11-05 (ADR 0018; test-matrix.md row 2). `test_passthrough.py` asserts the 2026-era half (netdev-ssh-mcp
  at 2026-07-28 stateless). Through `--policy` (M1-28, row 4's upa half):
  `send_command_and_get_output` with `show version` and `show ip bgp
  summary` downgraded to READ_OPERATIONAL and allowed by `reads-anywhere`,
  `reload` denied by `no-exec` with no SSH session, under read-only.yaml
  and prod-approval.yaml; `set_config_commands_and_commit_or_save` with
  `["end", "reload now"]` denied as EXEC_ARBITRARY and a plain line as
  WRITE_CONFIG; a device name not in the inventory denied by
  `default:unknown_target` for a read, a write and exec.
- Tier 2: live for shigechika/eos-mcp 1.3.0 (the PyPI wheel; every
  artifact in `requirements.txt` hash-checked, including the pyeapi 1.0.4
  sdist, which is built with the setuptools pinned and hashed in
  `build-constraints.txt`; each eos_mcp module checked against commit
  `bffb893`), CI job `tier2-eos-mcp`, no Docker (M1-22). `integration/test_eos_mcp.py` runs it behind
  `fathomgate serve` over stdio against the fake eAPI device
  (`fixtures/device/fake_eapi.py`):
  - `--no-policy`: the 17 tools as `eos-mcp.<tool>` at 2025-11-25 stateful,
    `show version` via `run_command` once on the device; `localhost`, which
    is in neither config.ini nor the inventory, reaches the device with the
    `[DEFAULT]` FAKE credentials (the control for the gated case); push_config with
    `dry_run` left at true still sends `end` and `reload now` in the same
    eAPI call as `configure session mcp-push`; `verify = true` in its
    config.ini does not stop it talking to a self-signed impostor.
  - `--policy` read-only.yaml with the embedded profile (the run_command
    case also under prod-approval.yaml, M1-28): `show version`
    and `show ip bgp summary` allowed by `reads-anywhere` (READ_OPERATIONAL,
    downgraded by the command) and run; `reload` denied
    by `no-exec`; `localhost` and `10.99.99.99` denied by
    `default:unknown_target` (for `localhost`, no connection reaches the
    device); `config_path` (any value, `""` included)
    denied by `default:bad_arguments`; push_config `["end", "reload now"]`
    denied by `no-exec` as EXEC_ARBITRARY and a plain line by `no-writes`;
    `collect_tech_support` allowed as READ_CONFIG, and denied as
    READ_CONFIG, like `run_command show tech-support`, under a policy that
    denies config reads. Each denial is the exact tool error and decision
    line; for every denied call that would otherwise reach the loopback
    fake, its connection log shows eos-mcp never connected.
  - This is the eos-mcp half of matrix row 4 in CI; with the upa half it
    closes the row (M1-28, test-matrix.md run notes).
- Tier 3: workflow skeleton only.
