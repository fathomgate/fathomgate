"""Schema linter for NetGuard policy YAML.

Mirrors ``internal/policy.Validate`` in Go so contributors without a Go
toolchain get the same errors: required keys, effect and class enums,
unknown keys, known obligations, approval only on hold rules, well-formed
ranges and durations, unique rule ids.

Usage::

    python -m policy_lint policies/examples/prod-approval.yaml

It checks shape only. Behaviour is asserted with ``netguard policy test``.
"""

from .lint import Finding, lint_file, lint_policy, main

__all__ = ["Finding", "lint_file", "lint_policy", "main"]
