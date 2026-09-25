# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 1 tests for policy_lint against the shipped example policies."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from policy_lint import Finding, lint_file, lint_policy, main, warn_policy

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = sorted(p for p in (REPO / "policies" / "examples").glob("*.yaml") if not p.name.endswith(".test.yaml"))

PLAN_POLICY = yaml.safe_load(
    """
version: 1
defaults:
  unknown_target: deny
  session:
    max_devices: 5
    max_pending: 2
rules:
  - id: reads-anywhere
    match: { class: [READ_OPERATIONAL, READ_CONFIG, INVENTORY_READ] }
    effect: allow
  - id: lab-writes-free
    match: { class: [WRITE_CONFIG], device_tags: [lab] }
    effect: allow
    obligations: [dry_run, diff]
  - id: prod-core-needs-approval
    match: { class: [WRITE_CONFIG], device_roles: [core, border] }
    effect: hold
    obligations: [dry_run, diff, timed_rollback]
    approval: { ttl: 15m, approver_must_differ: true }
  - id: fleet-cap
    match: { class: [WRITE_CONFIG] }
    when: { targets_count: { gt: 3 } }
    effect: deny
    reason: "fan-out above 3 devices needs a change ticket"
  - id: no-exec
    match: { class: [EXEC_ARBITRARY] }
    effect: deny
"""
)


@pytest.mark.tier1
def test_plan_policy_is_clean() -> None:
    assert lint_policy(PLAN_POLICY) == []


@pytest.mark.tier1
@pytest.mark.parametrize("path", EXAMPLES, ids=[p.name for p in EXAMPLES])
def test_shipped_examples_are_clean(path: Path) -> None:
    assert lint_file(path) == []


def _mutated(**changes):
    doc = copy.deepcopy(PLAN_POLICY)
    for dotted, value in changes.items():
        node = doc
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[int(part)] if part.isdigit() else node[part]
        last = parts[-1]
        if value is Ellipsis:
            del node[int(last) if last.isdigit() else last]
        else:
            node[int(last) if last.isdigit() else last] = value
    return doc


@pytest.mark.tier1
@pytest.mark.parametrize(
    ("changes", "needle"),
    [
        ({"version": 2}, "must be 1"),
        ({"version": ...}, "must be 1"),
        ({"rules": []}, "non-empty"),
        ({"rules": ...}, "non-empty"),
        ({"bogus": 1}, "unknown key"),
        ({"defaults.unknown_target": "hold"}, "allow or deny"),
        ({"defaults.session.max_devices": -1}, "non-negative"),
        ({"defaults.session.max_pods": 1}, "unknown key"),
        ({"rules.0.effect": "maybe"}, "must be one of"),
        ({"rules.0.match.class": ["NOPE"]}, "unknown class"),
        ({"rules.0.match.classes": ["READ_CONFIG"]}, "unknown key"),
        ({"rules.0.id": ...}, "id is required"),
        ({"rules.0.id": "default:x"}, "reserved"),
        ({"rules.1.id": "reads-anywhere"}, "duplicate rule id"),
        ({"rules.1.obligations": ["dry-run"]}, "unknown obligation"),
        ({"rules.0.approval": {"ttl": "1m"}}, "only valid with effect hold"),
        ({"rules.2.approval.ttl": "soon"}, "Go duration"),
        ({"rules.2.approval.ttl": 15}, "Go duration"),
        ({"rules.2.approval.approver_must_differ": "yes"}, "boolean"),
        ({"rules.3.when.targets_count": {}}, "at least one"),
        ({"rules.3.when.targets_count": {"gt": 3, "lt": 2}}, "never match"),
        ({"rules.3.when.targets_count.gt": "three"}, "must be an integer"),
        ({"rules.3.when.hour": {"gt": 3}}, "unknown key"),
        ({"rules.0.match.device_roles": "core"}, "list of strings"),
        ({"rules.0.matches": {}}, "unknown key"),
    ],
)
def test_findings(changes: dict, needle: str) -> None:
    findings = lint_policy(_mutated(**changes))
    assert findings, f"expected a finding for {changes}"
    assert any(needle in f.message for f in findings), [str(f) for f in findings]


@pytest.mark.tier1
def test_non_mapping_document() -> None:
    assert lint_policy([1, 2]) == [Finding("$", "policy must be a mapping")]


@pytest.mark.tier1
def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(yaml.safe_dump(PLAN_POLICY), encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nrules: [{id: a, effect: maybe}]\n", encoding="utf-8")

    assert main([str(good)]) == 0
    assert "ok" in capsys.readouterr().out
    assert main([str(good), str(bad)]) == 1
    out = capsys.readouterr().out
    assert "bad.yaml:$.rules[0].effect" in out


@pytest.mark.tier1
@pytest.mark.parametrize(
    ("unknown_target", "warned"),
    [("allow", True), ("deny", False), (None, False)],
)
def test_unknown_target_allow_warns(unknown_target: str | None, warned: bool) -> None:
    doc = copy.deepcopy(PLAN_POLICY)
    if unknown_target is None:
        del doc["defaults"]["unknown_target"]
    else:
        doc["defaults"]["unknown_target"] = unknown_target
    assert lint_policy(doc) == []
    warnings = warn_policy(doc)
    assert bool(warnings) is warned
    if warned:
        assert warnings[0].path == "$.defaults.unknown_target"
        assert "ADR 0032" in warnings[0].message


@pytest.mark.tier1
def test_cli_warning_keeps_exit_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = copy.deepcopy(PLAN_POLICY)
    doc["defaults"]["unknown_target"] = "allow"
    f = tmp_path / "allow.yaml"
    f.write_text(yaml.safe_dump(doc), encoding="utf-8")
    assert main([str(f)]) == 0
    out = capsys.readouterr().out
    assert "allow.yaml:$.defaults.unknown_target: warning:" in out
    assert "allow.yaml: ok" in out
