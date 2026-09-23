# NetGuard Python companion

Everything a contributor without a Go toolchain needs: a linter for policy
files, the redaction fixture corpus, and the integration tests that will run
against real upstream MCP servers once the proxy transport lands (M0).

```
tests/
  pyproject.toml        uv-friendly project: pytest, pyyaml, mcp
  policy_lint/          validate policy YAML against the DSL schema (python -m policy_lint)
  unit/                 tier 1: no network
  integration/          tier 2: spawn `netguard serve` + real MCP server (skipped until M0)
  fixtures/configs/     sanitised running-configs with annotated FAKE secrets
```

## Running

```sh
cd tests
uv run --extra dev pytest unit -q            # tier 1
uv run python -m policy_lint ../policies/examples/prod-approval.yaml
uv run pytest integration -q                 # tier 2 (currently all skipped)
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
- Tier 2: `integration/test_passthrough.py` shows the intended shape and is
  skipped with reason `M0: proxy transport not implemented`.
- Tier 3: workflow skeleton only.
