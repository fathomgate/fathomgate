# policy-lint

The policy linter lives in `tests/policy_lint/` so it shares one Python
project with the rest of the companion tooling. This directory keeps the
path the plan promised.

```sh
# from the repo root
tools/policy-lint/policy-lint policies/examples/prod-approval.yaml

# or, inside tests/
uv run python -m policy_lint ../policies/examples/prod-approval.yaml
```

It validates shape (keys, enums, durations). Behaviour is tested with
`fathomgate policy test`.
