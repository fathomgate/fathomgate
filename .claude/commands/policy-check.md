Run the policy test suite and linter against a policy file and explain every failure in the project's vocabulary. Usage: `/policy-check policies/examples/prod-approval.yaml`

Adopt the agent in `.claude/agents/policy-engineer.md` for this conversation.

Policy path: `$ARGUMENTS` (required; a `.yaml` policy file. If a directory is given, check every policy in it. If empty, check `policies/`).

Steps:

1. Confirm the file parses and the schema is valid: `make policy-lint POLICY=<path>` (falls back to `uv run tools/policy-lint/policy_lint.py <path>` if the Make target is absent). Report each schema finding as `line — field — problem — fix`, using the schema names from `docs/specs/policy-schema.md`: `version`, `defaults.unknown_target`, `defaults.session.max_devices`, `defaults.session.max_pending`, `rules[].id`, `match.class`, `match.device_roles`, `match.device_tags`, `match.tools`, `when.targets_count`, `effect`, `reason`, `obligations`, `approval.ttl`, `approval.approver_must_differ`.
2. Run the test suite: `make policy-test POLICY=<path>` (wraps `netguard policy test <path>`), which evaluates every `(request, expected decision)` case in the sibling `*.test.yaml` files. If no `*.test.yaml` exists beside the policy, say so and stop: a policy without tests is not checkable.
3. For every failing case, run `netguard policy eval --policy <path> --request <case>` (or reconstruct the case with `--tool`, `--arg`, `--role`, `--tag`, `--targets-count`) with `--trace` to get the rule trace, and explain in this exact shape:
   - Case name and the request (tool, class, target, roles, tags, targets count).
   - Expected: `<effect> <class> <target> <rule-id>` with obligations.
   - Got: the same shape from the trace.
   - Why: which rule matched first and why the expected rule did not (field mismatch, rule order, tie-break `deny` > `hold` > `allow` at equal specificity, `defaults.unknown_target`, or the `EXEC_ARBITRARY` downgrade rule not applying because a command failed the allow-list or hit the blocklist).
   - Fix: either the rule edit (reorder, narrow `match`, add `when`) or the test edit, and say which one is right given the policy's stated intent in its header comment.
4. Check the invariants a passing suite can still miss and report them as warnings: every rule has at least one firing case and one non-firing case; every `hold` rule has `approval.ttl`; every `WRITE_CONFIG` `allow` or `hold` rule lists `dry_run` and `diff` and, for `hold`, `timed_rollback`; `EXEC_ARBITRARY` is `deny` unless the header comment justifies otherwise; `defaults.unknown_target` is present; every `deny` rule has a `reason` that names the rule's intent so the agent's error will read "Denied by `<id>`: <reason>".
5. Print a summary line per policy: `<path>: lint <pass|fail>, tests <n passed>/<n total>, warnings <n>`.

Use effects `allow`, `hold`, `deny` and the terminal state `expired`; class names exactly; obligations `dry_run`, `diff`, `timed_rollback`. Do not edit the policy or tests unless asked; propose the edit as a diff.
