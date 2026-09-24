# NetGuard Python companion

Everything a contributor without a Go toolchain needs: a linter for policy
files, the redaction fixture corpus, and the tier 2 integration tests that run
`netguard serve` in front of real upstream MCP servers.

```
tests/
  pyproject.toml        uv-friendly project: pytest, pyyaml, mcp
  policy_lint/          validate policy YAML against the DSL schema (python -m policy_lint)
  unit/                 tier 1: no network
  integration/          tier 2: spawn `netguard serve` + real MCP server + fake device
  fixtures/configs/     sanitised running-configs with annotated FAKE secrets
  fixtures/device/      fake SSH device (asyncssh) and its canned transcripts
  conformance/          official MCP conformance suite vs netguard serve: relay.py, baselines (make conformance)
```

## Running

```sh
cd tests
uv run --extra dev pytest unit -q            # tier 1
uv run python -m policy_lint ../policies/examples/prod-approval.yaml
# tier 2: needs bin/netguard (make build) and netdev-ssh-mcp v1.6.6, either the
# release binary or `go install github.com/krisiasty/netdev-ssh-mcp@v1.6.6`
NETGUARD_UPSTREAM=/abs/path/to/netdev-ssh-mcp uv run --extra integration pytest integration -m tier2 -v
```

Policy *behaviour* is tested by the Go binary, not by Python:
`netguard policy test policies/examples/prod-approval.test.yaml` (or
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
- Tier 2: live for netdev-ssh-mcp v1.6.6 (CI job `client-smoke`, no Docker).
  `integration/test_passthrough.py` covers matrix row 1 (prefixed `tools/list`
  and a read-only call through to the fake device);
  `integration/test_launcher_path.py` covers row 22 (the PATH-stripped
  launcher). The M1 decision and audit cases are skipped until the pipeline
  is wired. Without `NETGUARD_UPSTREAM` the tier 2 tests skip; CI sets
  `NETGUARD_TIER2_REQUIRED=1` so they cannot skip there.
- Tier 3: workflow skeleton only.
