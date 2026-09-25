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
  fixtures/device/      fake SSH device (asyncssh) and its canned transcripts
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
```

Each upstream's cases skip when its variables are unset, so either set runs
alone; `-m tier2` runs both.

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
  - The M1 decision and audit cases are skipped until the pipeline is wired.
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
  at 2026-07-28 stateless).
- Tier 3: workflow skeleton only.
