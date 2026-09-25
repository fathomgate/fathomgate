# M1-28: rows 3, 4 and 6 (and row 5's M1 half) pass through serve --policy on netdev-ssh-mcp, upa and eos-mcp; conformance runs with a policy loaded

- **Task:** M1-28 — Validate rows 3, 4 and 6 through serve --policy against netdev-ssh-mcp, upa/mcp-netmiko-server and eos-mcp run_command
- **From → To:** test-engineer → go-reviewer (security-reviewer also reviews)
- **State now:** in review
- **Branch / PR:** `test/m1-28-real-servers` · [PR #195](https://github.com/fathomgate/fathomgate/pull/195)
- **Date:** 2026-09-25

## Done

- `tests/integration/conftest.py`: shared helpers for gated runs: `policy_args` (owner-only policy and inventory), `decision_lines` (parses the `msg=decision` slog lines), `LoggedSession` (python-sdk stdio session with stderr to a file), `gate_error`, `result_text`, and the example policies' reasons.
- `tests/integration/test_policy_gate.py` (netdev-ssh-mcp v1.7.1), rewritten:
  - Row 3, and the netdev side of row 4, under read-only and prod-approval.
  - Row 6 for four classes under read-only, prod-approval and an unset-`unknown_target` policy that allows every class.
  - A `--no-policy` control showing that `localhost` reaches the device.
- `tests/integration/test_upa_netmiko.py`: row 4 upa half under both policies, with the downgrade (`class_source=downgrade`); `["end", "reload now"]` as EXEC_ARBITRARY; an unknown device name denied for a read, a write and exec.
- `tests/integration/test_eos_mcp.py`: the `run_command` case is parametrised over both policies.
- `tests/integration/test_passthrough.py`: the skip reason on the two audit cases now says they wait for M4.
- Conformance:
  - New leg `fathomgate-policy`: `tests/conformance/policy/{policy.yaml,profiles/conf.yaml}`.
  - `run.sh`: gate args, owner-only copy with `icacls` on Windows, and log checks after the suite.
  - New baselines `baseline/fathomgate-policy-{2025-11-25,2026-07-28}.yml`; `CONFORMANCE_LEGS` in the Makefile; README section "The policy leg".
- Docs:
  - `docs/testing/test-matrix.md`: rows 3 and 4 `passing`, row 6 `passing for the decision`, with run notes.
  - `tests/README.md`, `docs/testing/test-strategy.md`, `tests/fixtures/device/README.md` (the blocked cEOS items), CHANGELOG.
  - CI step names.
- **Row 5, M1 half** (scope added by the coordinator after PR #194 split the row), in `test_upa_netmiko.py` and `test_eos_mcp.py`:
  - `show running-config` in four whitespace variants is READ_CONFIG with `class_source=reclassify`.
  - Under read-only it is allowed and runs on the device. On upa only the space variants are sent: netmiko's interactive shell cannot carry a tab.
  - Under a policy that denies READ_CONFIG it is denied by `no-config-reads` and nothing is forwarded.
  - The row text is not edited while #194 is open. The matrix run notes give the wording to set when it merges.
- Board: M1-28 in review, matrix `[3, 4, 5, 6]`. `main` had already moved M1-22 and M1-23 to merged; the merge keeps its notes.

## Look at this first

- `tests/conformance/run.sh`, the block after the suite run for `gate=policy`. The greps depend on the slog attribute order of the decision line (`server tool class class_source ... decision rule_id ... forwarded`). If that order changes, the leg fails loudly and does not pass silently.
- `test_row6_unknown_host_denied_for_every_class[unset-allow-every-class]`: the only case where the rules would allow every class, so only the ADR 0032 default can be what denies.

## Deliberately unfinished

- **Blocked, not run** (M1-28 notes; recorded in the matrix run notes and the device README):
  - cEOS: push_config lines after `end` in one eAPI call; `clock set`, `watch` and `terminal` in configuration mode; `alias hn reload now`.
  - vMX or cRPD: whether an abbreviated-hierarchy text load is refused.
  - Why: no licensed image can be pulled in public CI. `nightly-clab.yaml` is off (`FATHOMGATE_CLAB_ENABLED`), and `tests/clab/` does not exist.
- Row 6's audit-event half waits for `--audit` in M4. M1-24 moves it in the matrix text.
- Exit criteria are not ticked. The evidence is in the matrix: criterion 3 on the real servers, criterion 2 with 45 of 45 policy cases. Criterion 1 depends on M1-15 and M1-17.
- M1-22 and M1-28 move to `validated` after this PR merges and the rows are green on `main`.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
make build conformance PYTHON=python3                       # includes fathomgate-policy, both revisions
tests/conformance/run.sh fathomgate-policy 2026-07-28      # one leg
cd tests && FATHOMGATE_UPSTREAM=... FATHOMGATE_UPA_DIR=... FATHOMGATE_UPA_PYTHON=... FATHOMGATE_UPA_LOCKED_PYTHON=... FATHOMGATE_EOS_MCP=... \
  uv run --extra integration pytest integration -m tier2 -v
```

CI [run 36200510504](https://github.com/fathomgate/fathomgate/actions/runs/36200510504) at `7e94ce0`:

| Job | Result |
| --- | --- |
| tier2 client smoke (netdev-ssh-mcp) | 38 passed, 2 skipped, 1 xfailed |
| tier2 upa/mcp-netmiko-server (2025 era) | 12 passed |
| tier2 eos-mcp (eAPI, --policy) | 12 passed |
| mcp-conformance | every leg within its baseline; `gate checks passed` on both policy revisions |

CI [run 36201094163](https://github.com/fathomgate/fathomgate/actions/runs/36201094163) at `bae1f6d` (after `origin/main` was merged in and the row 5 cases were added): every job green. netdev-ssh-mcp gave 38 passed, 2 skipped, 1 xfailed; upa gave 14 passed; eos-mcp gave 14 passed.

Local run on Windows 11: tier 2 gave 52 passed, 12 skipped and 1 xfailed, and the policy leg passed on both revisions. Mutation check: with `--no-policy` in place of the policy, the five gated netdev cases fail.

## Decisions made without an ADR

- The conformance test profile deliberately makes `test_error_handling` EXEC_ARBITRARY and leaves `test_x_mcp_header`'s `level` unnamed. That way the suite scores the deny tool error and the narrowed schema. As a result the plain fixture error is not scored on this leg; the `fathomgate` leg still scores it.
- The policy leg runs only against the current upstream. On the 2025 upstream, the fresh-process elicitation runs must pass, which a gated chain cannot do.

## Questions for the receiver

- For the maintainer, a product and infra decision: where tier 3 runs. The options are loading cEOS or vJunos on a `clab` runner and enabling `nightly-clab.yaml`, or dropping the device checks from M1. Without that, the cEOS and vMX items stay blocked.
