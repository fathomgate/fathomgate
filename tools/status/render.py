#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Render STATUS.md from docs/milestones/<current>.yaml and docs/handoffs/.

Usage:
  python3 tools/status/render.py            # rewrite STATUS.md
  python3 tools/status/render.py --check    # exit 1 if STATUS.md is stale (CI)

On Windows use `python` (or `make status PYTHON=python`); `python3` there is a
Microsoft Store alias.

The current milestone is the one named in docs/milestones/CURRENT (one line).
Requires PyYAML (`pip install pyyaml`, or `uv run` inside tests/).

Every file is read as UTF-8 and STATUS.md is written as UTF-8 with LF line
endings, whatever the platform defaults are, so the output is byte-identical
on every OS. `--check` compares those exact bytes against the file on disk.
"""
from __future__ import annotations

import pathlib
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("tools/status/render.py: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parents[2]
MILESTONES = ROOT / "docs" / "milestones"
HANDOFFS = ROOT / "docs" / "handoffs"
STATUS = ROOT / "STATUS.md"

ENCODING = "utf-8"

STATES = ["open", "blocked", "in progress", "in review", "merged", "validated", "dropped"]
# <date>-<from-slug>-to-<to-slug>-<task-id>.md ; slugs may contain hyphens, the task id may not.
HANDOFF_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-(.+?)-to-(.+)-([^-]+)\.md$")


def load_current() -> tuple[str, dict]:
    cur = (MILESTONES / "CURRENT").read_text(encoding=ENCODING).strip()
    path = MILESTONES / f"{cur}.yaml"
    data = yaml.safe_load(path.read_text(encoding=ENCODING))
    if data.get("milestone") != cur:
        sys.exit(f"{path}: milestone field {data.get('milestone')!r} != CURRENT {cur!r}")
    return cur, data


def validate(data: dict) -> list[str]:
    errs: list[str] = []
    ids = set()
    for t in data.get("tasks", []):
        for k in ("id", "title", "package", "owner", "state"):
            if k not in t:
                errs.append(f"task {t.get('id','?')}: missing {k}")
        if t.get("state") not in STATES:
            errs.append(f"task {t.get('id')}: bad state {t.get('state')!r}")
        if t["id"] in ids:
            errs.append(f"task {t['id']}: duplicate id")
        ids.add(t["id"])
    for t in data.get("tasks", []):
        for b in t.get("blocked_by", []):
            if b not in ids:
                errs.append(f"task {t['id']}: blocked_by unknown task {b}")
    return errs


def effective_state(t: dict, by_id: dict) -> str:
    if t["state"] == "open" and any(by_id[b]["state"] not in ("merged", "validated", "dropped") for b in t.get("blocked_by", [])):
        return "blocked"
    return t["state"]


def latest_handoffs(n: int = 5) -> list[tuple[str, str, str, str, str]]:
    out = []
    if not HANDOFFS.exists():
        return out
    for p in sorted(HANDOFFS.glob("*.md"), reverse=True):
        m = HANDOFF_RE.match(p.name)
        if not m:
            continue
        date, frm, to, task = m.groups()
        first = ""
        for line in p.read_text(encoding=ENCODING).splitlines():
            if line.startswith("# "):
                first = line[2:].strip()
                break
        out.append((date, frm, to, task, f"docs/handoffs/{p.name}", first))
        if len(out) >= n:
            break
    return out



def criterion_line(c) -> str:
    """One exit criterion: a string is open; a mapping with `met` is ticked."""
    if isinstance(c, dict):
        if c.get("met"):
            return f"- [x] {c['text']} — met {c['met']}"
        return f"- [ ] {c['text']}"
    return f"- [ ] {c}"

def adr_link(num) -> str:
    if not num:
        return "—"
    num = str(num).zfill(4)
    hits = sorted((ROOT / "docs" / "adr").glob(f"{num}-*.md"))
    if hits:
        return f"[{num}](docs/adr/{hits[0].name})"
    return f"{num} (missing)"


def render(cur: str, data: dict) -> str:
    by_id = {t["id"]: t for t in data.get("tasks", [])}
    lines: list[str] = []
    lines.append("# Status")
    lines.append("")
    lines.append("<!-- GENERATED from docs/milestones/" + cur + ".yaml by tools/status/render.py. Edit the YAML, then `make status`. -->")
    lines.append("")
    lines.append(f"**Current milestone:** {cur} — {data.get('title','')} · **state:** {data.get('status','')} · opened {data.get('opened','')}")
    lines.append("")
    counts = {}
    for t in data.get("tasks", []):
        s = effective_state(t, by_id)
        counts[s] = counts.get(s, 0) + 1
    lines.append("Tasks: " + " · ".join(f"{s} {counts[s]}" for s in STATES if s in counts))
    lines.append("")
    if data.get("blockers"):
        lines.append("## Blockers")
        lines.append("")
        for b in data["blockers"]:
            lines.append(f"- **{b['id']}** ({b.get('owner','unassigned')}): {b['text']}")
        lines.append("")
    lines.append("## In flight")
    lines.append("")
    lines.append("| Task | Title | Package | Owner | Reviewers | State | Blocked by | Matrix | ADR |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for t in data.get("tasks", []):
        s = effective_state(t, by_id)
        if s in ("validated", "dropped"):
            continue
        lines.append("| {id} | {title} | `{pkg}` | {owner} | {rev} | {state} | {bb} | {mx} | {adr} |".format(
            id=t["id"], title=t["title"], pkg=t["package"], owner=t["owner"],
            rev=", ".join(t.get("reviewers", [])) or "—", state=s,
            bb=", ".join(t.get("blocked_by", [])) or "—",
            mx=", ".join(str(x) for x in t.get("matrix", [])) or "—",
            adr=adr_link(t.get("adr"))))
    lines.append("")
    done = [t for t in data.get("tasks", []) if t["state"] in ("validated", "dropped")]
    if done:
        lines.append("## Done this milestone")
        lines.append("")
        for t in done:
            lines.append(f"- {t['id']} {t['title']} — {t['state']}")
        lines.append("")
    if data.get("exit_criteria"):
        lines.append("## Exit criteria")
        lines.append("")
        for c in data["exit_criteria"]:
            lines.append(criterion_line(c))
        lines.append("")
        lines.append("Validated against: " + ", ".join(f"`{s}`" for s in data.get("validates_against", [])))
        lines.append("")
    if data.get("external"):
        lines.append("## External")
        lines.append("")
        for e in data["external"]:
            lines.append(f"- {e['kind']}: {e['ref']} — {e['state']}. {e.get('note','')}".rstrip())
        lines.append("")
    lines.append("## Last handoffs")
    lines.append("")
    hs = latest_handoffs()
    if not hs:
        lines.append("_none yet_")
    else:
        lines.append("| Date | From | To | Task | Note |")
        lines.append("| --- | --- | --- | --- | --- |")
        for date, frm, to, task, path, first in hs:
            lines.append(f"| {date} | {frm} | {to} | {task} | [{first or path}]({path}) |")
    lines.append("")
    lines.append("## How to update")
    lines.append("")
    lines.append(f"Edit `docs/milestones/{cur}.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).")
    lines.append("")
    return "\n".join(lines)


def encode(text: str) -> bytes:
    """The exact bytes STATUS.md must hold: UTF-8, LF line endings."""
    return text.encode(ENCODING)


def write_status(path: pathlib.Path, text: str) -> None:
    """Write text as UTF-8 with LF, ignoring the platform's defaults."""
    with open(path, "w", encoding=ENCODING, newline="\n") as f:
        f.write(text)


def is_current(path: pathlib.Path, text: str) -> bool:
    """True if the file on disk holds exactly the bytes write_status would write."""
    current = path.read_bytes() if path.exists() else b""
    return current == encode(text)


def main(argv: list[str]) -> int:
    cur, data = load_current()
    errs = validate(data)
    if errs:
        for e in errs:
            sys.stderr.write(f"{MILESTONES / (cur + '.yaml')}: {e}\n")
        return 1
    text = render(cur, data)
    if "--check" in argv:
        if not is_current(STATUS, text):
            sys.stderr.write("STATUS.md is stale: run `make status` and commit the result\n")
            return 1
        print("STATUS.md is current")
        return 0
    write_status(STATUS, text)
    print(f"wrote {STATUS.relative_to(ROOT)} from docs/milestones/{cur}.yaml")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
