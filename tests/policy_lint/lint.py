"""Policy schema linter. See package docstring."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CLASSES = {
    "READ_OPERATIONAL",
    "READ_CONFIG",
    "WRITE_CONFIG",
    "EXEC_ARBITRARY",
    "INVENTORY_READ",
    "LAB_LIFECYCLE",
    "LOCAL_ADMIN",
}
EFFECTS = {"allow", "hold", "deny"}
OBLIGATIONS = {
    "dry_run",
    "diff",
    "timed_rollback",
    "redact",
    "canary_first",
    "require_ticket",
    "notify",
}

TOP_KEYS = {"version", "defaults", "rules"}
DEFAULTS_KEYS = {"unknown_target", "session"}
SESSION_KEYS = {"max_devices", "max_pending"}
RULE_KEYS = {"id", "match", "when", "effect", "reason", "obligations", "approval"}
MATCH_KEYS = {"class", "device_roles", "device_tags", "tools", "servers"}
WHEN_KEYS = {"targets_count"}
RANGE_KEYS = {"gt", "gte", "lt", "lte", "eq"}
APPROVAL_KEYS = {"ttl", "approver_must_differ"}

# Go time.ParseDuration syntax: 15m, 1h30m, 90s, 1.5h.
DURATION_RE = re.compile(r"^([0-9]*\.?[0-9]+(ns|us|µs|ms|s|m|h))+$")


@dataclass(frozen=True)
class Finding:
    """One lint problem, addressed by a JSON-pointer-like path."""

    path: str
    message: str

    def __str__(self) -> str:  # pragma: no cover - formatting only
        return f"{self.path}: {self.message}"


def _unknown(node: dict, allowed: set[str], path: str, out: list[Finding]) -> None:
    for key in node:
        if key not in allowed:
            out.append(Finding(f"{path}.{key}", f"unknown key (allowed: {', '.join(sorted(allowed))})"))


def _str_list(value: Any, path: str, out: list[Finding]) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        out.append(Finding(path, "must be a list of strings"))
        return []
    return value


def lint_policy(doc: Any) -> list[Finding]:
    """Return every finding for a parsed policy document (empty when valid)."""
    out: list[Finding] = []
    if not isinstance(doc, dict):
        return [Finding("$", "policy must be a mapping")]

    _unknown(doc, TOP_KEYS, "$", out)
    if doc.get("version") != 1:
        out.append(Finding("$.version", "must be 1"))

    defaults = doc.get("defaults", {})
    if defaults is not None:
        if not isinstance(defaults, dict):
            out.append(Finding("$.defaults", "must be a mapping"))
        else:
            _unknown(defaults, DEFAULTS_KEYS, "$.defaults", out)
            ut = defaults.get("unknown_target")
            if ut is not None and ut not in {"allow", "deny"}:
                out.append(Finding("$.defaults.unknown_target", "must be allow or deny"))
            session = defaults.get("session")
            if session is not None:
                if not isinstance(session, dict):
                    out.append(Finding("$.defaults.session", "must be a mapping"))
                else:
                    _unknown(session, SESSION_KEYS, "$.defaults.session", out)
                    for k in SESSION_KEYS:
                        v = session.get(k)
                        if v is not None and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                            out.append(Finding(f"$.defaults.session.{k}", "must be a non-negative integer"))

    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        out.append(Finding("$.rules", "must be a non-empty list"))
        return out

    seen: set[str] = set()
    for i, rule in enumerate(rules):
        p = f"$.rules[{i}]"
        if not isinstance(rule, dict):
            out.append(Finding(p, "rule must be a mapping"))
            continue
        _unknown(rule, RULE_KEYS, p, out)

        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            out.append(Finding(f"{p}.id", "id is required"))
        else:
            if rid.startswith("default:"):
                out.append(Finding(f"{p}.id", "the default: prefix is reserved"))
            if rid in seen:
                out.append(Finding(f"{p}.id", f"duplicate rule id {rid!r}"))
            seen.add(rid)

        effect = rule.get("effect")
        if effect not in EFFECTS:
            out.append(Finding(f"{p}.effect", f"must be one of {', '.join(sorted(EFFECTS))}"))

        match = rule.get("match")
        if match is not None:
            if not isinstance(match, dict):
                out.append(Finding(f"{p}.match", "must be a mapping"))
            else:
                _unknown(match, MATCH_KEYS, f"{p}.match", out)
                for cls in _str_list(match.get("class", []), f"{p}.match.class", out):
                    if cls not in CLASSES:
                        out.append(Finding(f"{p}.match.class", f"unknown class {cls!r}"))
                for key in ("device_roles", "device_tags", "tools", "servers"):
                    if key in match:
                        _str_list(match[key], f"{p}.match.{key}", out)

        when = rule.get("when")
        if when is not None:
            if not isinstance(when, dict):
                out.append(Finding(f"{p}.when", "must be a mapping"))
            else:
                _unknown(when, WHEN_KEYS, f"{p}.when", out)
                tc = when.get("targets_count")
                if tc is not None:
                    if not isinstance(tc, dict) or not tc:
                        out.append(Finding(f"{p}.when.targets_count", "must set at least one of gt, gte, lt, lte, eq"))
                    else:
                        _unknown(tc, RANGE_KEYS, f"{p}.when.targets_count", out)
                        for k, v in tc.items():
                            if k in RANGE_KEYS and (not isinstance(v, int) or isinstance(v, bool)):
                                out.append(Finding(f"{p}.when.targets_count.{k}", "must be an integer"))
                        gt, lt = tc.get("gt"), tc.get("lt")
                        if isinstance(gt, int) and isinstance(lt, int) and gt >= lt:
                            out.append(Finding(f"{p}.when.targets_count", f"gt {gt} >= lt {lt} can never match"))

        obligations = rule.get("obligations")
        if obligations is not None:
            for ob in _str_list(obligations, f"{p}.obligations", out):
                if ob not in OBLIGATIONS:
                    out.append(Finding(f"{p}.obligations", f"unknown obligation {ob!r} (known: {', '.join(sorted(OBLIGATIONS))})"))

        approval = rule.get("approval")
        if approval is not None:
            if effect != "hold":
                out.append(Finding(f"{p}.approval", "approval is only valid with effect hold"))
            if not isinstance(approval, dict):
                out.append(Finding(f"{p}.approval", "must be a mapping"))
            else:
                _unknown(approval, APPROVAL_KEYS, f"{p}.approval", out)
                ttl = approval.get("ttl")
                if ttl is not None and (not isinstance(ttl, str) or not DURATION_RE.match(ttl)):
                    out.append(Finding(f"{p}.approval.ttl", "must be a Go duration such as 15m or 1h30m"))
                amd = approval.get("approver_must_differ")
                if amd is not None and not isinstance(amd, bool):
                    out.append(Finding(f"{p}.approval.approver_must_differ", "must be a boolean"))
    return out


def lint_file(path: str | Path) -> list[Finding]:
    """Lint one YAML file. A YAML syntax error is reported as a single finding."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - depends on input
        return [Finding("$", f"YAML error: {exc}")]
    return lint_policy(doc)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: exit 0 when every file is clean, 1 otherwise."""
    parser = argparse.ArgumentParser(prog="policy-lint", description="Lint Fathomgate policy YAML files.")
    parser.add_argument("files", nargs="+", help="policy files to check")
    args = parser.parse_args(argv)
    bad = 0
    for f in args.files:
        if f.endswith(".test.yaml"):
            print(f"{f}: skipped (policy test file, run `fathomgate policy test` instead)")
            continue
        findings = lint_file(f)
        if findings:
            bad += 1
            for fd in findings:
                print(f"{f}:{fd.path}: {fd.message}")
        else:
            print(f"{f}: ok")
    return 1 if bad else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
