#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Make the GitHub issue mirror follow docs/milestones/*.yaml (M1-38).

Usage:
  python tools/status/issues.py                  # dry run: print the plan and the drift report
  python tools/status/issues.py --apply          # make the changes (CI: issue-hygiene.yaml)
  python tools/status/issues.py --summary FILE   # also append the report as Markdown (job summary)
  python tools/status/issues.py --repo OWNER/NAME

The board is the source of truth (docs/handoffs/README.md). For every task on
every board, the issues whose title starts with the task id get:

- exactly one `state:<state>` label, the task's effective state as STATUS.md
  shows it (an `open` task with an unmerged `blocked_by` is `blocked`);
- exactly one `milestone:<Mn>` label;
- exactly one `agent:<owner>` label when the owner is an agent slug in
  .github/labels.yml (a human owner's issue keeps its agent labels as they are);
- when the task is `merged`, `validated` or `dropped` and the issue is open:
  closed (`dropped` as not planned, the others as completed) with a one-line
  comment that names the PR when the task notes mention `PR #N`.

It reports, and never changes: open issues whose title starts with a task id
that is on no board; active tasks with no issue; closed issues of active
tasks; tasks with more than one issue; task-id issues opened by someone who
is not an owner, member or collaborator (never touched, so an outside issue
titled like a task cannot be relabelled or closed by the job); and open issues
of any kind with no activity in 30 days. An issue without a task-id prefix is
only ever read for the 30-day report. A missing label that .github/labels.yml
defines is created first.

Running it twice changes nothing the second time: labels are compared with
what the issue has, and only open issues are closed and commented on.

GitHub is reached through the `gh` CLI (`gh api`), not urllib with a token:
`gh` is on every hosted runner and on every maintainer's machine already
authenticated, it follows pagination, and the token stays in `gh`'s own
keyring or in GH_TOKEN, never in this script's arguments or memory. The tests
replace the one `GitHub` class with a fake.

Requires PyYAML, like render.py (`uv run --no-project --with pyyaml python ...`).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.parse

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("tools/status/issues.py: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parents[2]
MILESTONES = ROOT / "docs" / "milestones"
LABELS_YML = ROOT / ".github" / "labels.yml"
ENCODING = "utf-8"


def _load_render():
    spec = importlib.util.spec_from_file_location("status_render", pathlib.Path(__file__).with_name("render.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


render = _load_render()

# Board ids look like T0.14 (M0) or M1-38 (M1 on). A title prefix is the id
# followed by whitespace, a colon or the end of the title.
TASK_ID_RE = re.compile(r"^(T\d+\.\d+|M\d+-\d+)(?=[\s:]|$)")
CLOSING = {"merged": "completed", "validated": "completed", "dropped": "not_planned"}
TRUSTED = {"OWNER", "MEMBER", "COLLABORATOR"}
STALE_DAYS = 30
# "Merged in PR #14", "Merged in #20": the merging PR, preferred over other mentions.
MERGED_PR_RE = re.compile(r"\bmerged\s+(?:in|as|via|by)\s+(?:PR\s+)?#(\d+)", re.IGNORECASE)
PR_RE = re.compile(r"\bPR\s+#(\d+)")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclasses.dataclass(frozen=True)
class Task:
    id: str
    title: str
    milestone: str
    owner: str
    state: str  # effective state, as STATUS.md shows it
    notes: str
    board: str  # docs/milestones/<Mn>.yaml


@dataclasses.dataclass(frozen=True)
class Issue:
    number: int
    title: str
    state: str  # "open" or "closed"
    labels: tuple[str, ...]
    updated_at: dt.datetime
    author_association: str = "OWNER"
    state_reason: str | None = None


@dataclasses.dataclass
class Change:
    issue: Issue
    task: Task
    add: list[str]
    remove: list[str]
    close_reason: str | None = None
    comment: str | None = None


@dataclasses.dataclass
class Plan:
    repo: str
    tasks: int
    issues: int
    create_labels: list[str]
    changes: list[Change]
    unknown_task: list[Issue]
    missing_issue: list[Task]
    closed_active: list[tuple[Issue, Task]]
    duplicates: list[tuple[Task, list[Issue]]]
    untrusted: list[Issue]
    human_owner: list[tuple[Issue, Task]]
    stale: list[Issue]


# ---------------------------------------------------------------- inputs


def load_tasks(milestones: pathlib.Path | None = None) -> list[Task]:
    """Every task on every docs/milestones/*.yaml, with its effective state."""
    milestones = milestones or MILESTONES
    boards = []
    errs = []
    for path in sorted(milestones.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding=ENCODING)) or {}
        for e in render.validate(data):
            errs.append(f"{path.name}: {e}")
        boards.append((path, data))
    if errs:
        raise SystemExit("\n".join(errs))
    by_id = {t["id"]: t for _, d in boards for t in d.get("tasks", [])}
    out = []
    for path, data in boards:
        ms = str(data.get("milestone") or path.stem)
        for t in data.get("tasks", []):
            out.append(Task(
                id=t["id"], title=t["title"], milestone=ms, owner=str(t["owner"]),
                state=render.effective_state(t, by_id), notes=str(t.get("notes") or ""),
                board=f"docs/milestones/{path.name}"))
    return out


def load_label_defs(path: pathlib.Path | None = None) -> dict[str, dict]:
    path = path or LABELS_YML
    return {d["name"]: d for d in yaml.safe_load(path.read_text(encoding=ENCODING)) or []}


# ---------------------------------------------------------------- GitHub


class GitHub:
    """The only code that talks to GitHub: `gh api` against one repository."""

    def __init__(self, repo: str, gh: str = "gh"):
        self.repo = repo
        self.gh = gh

    def _api(self, *args: str, body: dict | None = None) -> str:
        cmd = [self.gh, "api", "-H", "Accept: application/vnd.github+json", *args]
        if body is not None:
            cmd += ["--input", "-"]
        r = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True, encoding=ENCODING, check=False)
        if r.returncode != 0:
            raise RuntimeError(f"gh api {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout

    def list_issues(self) -> list[Issue]:
        jq = ('.[] | select(has("pull_request") | not) | {number, title, state, state_reason, '
              'updated_at, author_association, labels: [.labels[].name]}')
        out = self._api("--paginate", f"repos/{self.repo}/issues?state=all&per_page=100", "--jq", jq)
        issues = []
        for line in out.splitlines():
            if line.strip():
                d = json.loads(line)
                issues.append(Issue(
                    number=d["number"], title=d["title"], state=d["state"],
                    labels=tuple(d["labels"]), updated_at=parse_time(d["updated_at"]),
                    author_association=d.get("author_association") or "NONE",
                    state_reason=d.get("state_reason")))
        return issues

    def list_labels(self) -> set[str]:
        out = self._api("--paginate", f"repos/{self.repo}/labels?per_page=100", "--jq", ".[].name")
        return {line for line in out.splitlines() if line}

    def create_label(self, name: str, color: str, description: str) -> None:
        self._api("-X", "POST", f"repos/{self.repo}/labels",
                  body={"name": name, "color": color, "description": description})

    def add_labels(self, number: int, labels: list[str]) -> None:
        self._api("-X", "POST", f"repos/{self.repo}/issues/{number}/labels", body={"labels": labels})

    def remove_label(self, number: int, label: str) -> None:
        self._api("-X", "DELETE", f"repos/{self.repo}/issues/{number}/labels/{urllib.parse.quote(label, safe='')}")

    def close(self, number: int, reason: str) -> None:
        self._api("-X", "PATCH", f"repos/{self.repo}/issues/{number}",
                  body={"state": "closed", "state_reason": reason})

    def comment(self, number: int, body: str) -> None:
        self._api("-X", "POST", f"repos/{self.repo}/issues/{number}/comments", body={"body": body})


def parse_time(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def resolve_repo(arg: str | None) -> str:
    if arg:
        return arg
    if os.environ.get("GITHUB_REPOSITORY"):
        return os.environ["GITHUB_REPOSITORY"]
    r = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "-q", ".nameWithOwner"],
                       capture_output=True, text=True, encoding=ENCODING, check=False, cwd=ROOT)
    if r.returncode != 0 or not r.stdout.strip():
        raise SystemExit(f"cannot tell the repository; pass --repo OWNER/NAME ({r.stderr.strip()})")
    return r.stdout.strip()


# ---------------------------------------------------------------- planning


def task_id(title: str) -> str | None:
    m = TASK_ID_RE.match(title)
    return m.group(1) if m else None


def pr_of(notes: str) -> int | None:
    """The PR a task's notes name: the one it was merged in, else the last PR #N mentioned."""
    m = MERGED_PR_RE.search(notes)
    if m:
        return int(m.group(1))
    prs = PR_RE.findall(notes)
    return int(prs[-1]) if prs else None


def close_comment(t: Task) -> str:
    pr = pr_of(t.notes)
    ref = f", PR #{pr}" if pr else ""
    return f"{t.id} is `{t.state}` on the board ({t.board}{ref}); closed by tools/status/issues.py."


def wanted_labels(t: Task, have: tuple[str, ...], agents: set[str]) -> tuple[list[str], list[str]]:
    """Labels to add and to remove so the issue mirrors the task."""
    want = {f"state:{t.state}", f"milestone:{t.milestone}"}
    prefixes = ["state:", "milestone:"]
    if t.owner in agents:
        want.add(f"agent:{t.owner}")
        prefixes.append("agent:")
    add = sorted(want - set(have))
    remove = sorted(label for label in have if label not in want and any(label.startswith(p) for p in prefixes))
    return add, remove


def plan(repo: str, tasks: list[Task], issues: list[Issue], repo_labels: set[str],
         label_defs: dict[str, dict], now: dt.datetime) -> Plan:
    agents = {n.split(":", 1)[1] for n in label_defs if n.startswith("agent:")}
    by_task: dict[str, list[Issue]] = {}
    untrusted: list[Issue] = []
    for i in sorted(issues, key=lambda i: i.number):
        tid = task_id(i.title)
        if tid is None:
            continue
        if i.author_association not in TRUSTED:
            untrusted.append(i)
            continue
        by_task.setdefault(tid, []).append(i)

    board = {t.id: t for t in tasks}
    changes: list[Change] = []
    needed: set[str] = set()
    missing, closed_active, dups, human = [], [], [], []
    for t in tasks:
        mine = by_task.get(t.id, [])
        active = t.state not in CLOSING
        if not mine:
            if active:
                missing.append(t)
            continue
        if len(mine) > 1:
            dups.append((t, mine))
        for i in mine:
            if t.owner not in agents:
                human.append((i, t))
            add, remove = wanted_labels(t, i.labels, agents)
            needed.update(add)
            c = Change(issue=i, task=t, add=add, remove=remove)
            if i.state == "open" and not active:
                c.close_reason = CLOSING[t.state]
                c.comment = close_comment(t)
            elif i.state == "closed" and active:
                closed_active.append((i, t))
            if c.add or c.remove or c.close_reason:
                changes.append(c)

    unknown = [i for tid, lst in sorted(by_task.items()) if tid not in board for i in lst if i.state == "open"]
    unknown += [i for i in untrusted if i.state == "open" and task_id(i.title) not in board]
    cutoff = now - dt.timedelta(days=STALE_DAYS)
    stale = [i for i in sorted(issues, key=lambda i: i.number) if i.state == "open" and i.updated_at < cutoff]
    return Plan(repo=repo, tasks=len(tasks), issues=len(issues),
                create_labels=sorted(needed - repo_labels), changes=changes,
                unknown_task=sorted(unknown, key=lambda i: i.number), missing_issue=missing,
                closed_active=closed_active, duplicates=dups, untrusted=untrusted,
                human_owner=human, stale=stale)


def apply(p: Plan, gh: GitHub, label_defs: dict[str, dict]) -> None:
    for name in p.create_labels:
        d = label_defs.get(name, {})
        gh.create_label(name, str(d.get("color", "ededed")), str(d.get("description", "")))
    for c in p.changes:
        n = c.issue.number
        if c.add:
            gh.add_labels(n, c.add)
        for label in c.remove:
            gh.remove_label(n, label)
        if c.close_reason:
            # Close first: if the comment then fails, a re-run finds the issue
            # closed and does not comment twice.
            gh.close(n, c.close_reason)
            gh.comment(n, c.comment)


# ---------------------------------------------------------------- output


def clean(title: str) -> str:
    """An issue title is untrusted: no control characters in logs or the summary."""
    return CONTROL_RE.sub(" ", title)


def md(title: str) -> str:
    """Escape an untrusted title for a Markdown table cell or list item."""
    s = clean(title)
    for ch in "\\`*_[]<>|#!":
        s = s.replace(ch, "\\" + ch)
    return s


def change_line(c: Change) -> str:
    parts = []
    if c.add:
        parts.append("add " + ", ".join(c.add))
    if c.remove:
        parts.append("remove " + ", ".join(c.remove))
    if c.close_reason:
        parts.append(f"close as {c.close_reason.replace('_', ' ')}")
    return f"#{c.issue.number} {c.task.id} ({c.task.state}): " + "; ".join(parts)


def drift_sections(p: Plan, fmt) -> list[tuple[str, list[str]]]:
    return [
        ("Open issues whose task id is on no board", [f"#{i.number} {fmt(i.title)}" for i in p.unknown_task]),
        ("Active board tasks with no issue", [f"{t.id} ({t.state}, {t.board}) {fmt(t.title)}" for t in p.missing_issue]),
        ("Closed issues of active tasks (not reopened)", [f"#{i.number} {t.id} is {t.state}" for i, t in p.closed_active]),
        ("Tasks with more than one issue", [f"{t.id}: " + ", ".join(f"#{i.number}" for i in lst) for t, lst in p.duplicates]),
        ("Task-id issues from outside collaborators (not touched)",
         [f"#{i.number} ({i.author_association}) {fmt(i.title)}" for i in p.untrusted]),
        ("Issues of tasks owned by a human (agent labels left as they are)",
         [f"#{i.number} {t.id} owner {t.owner}" for i, t in p.human_owner]),
        (f"Open issues with no activity in {STALE_DAYS} days (report only)",
         [f"#{i.number} last updated {i.updated_at.date().isoformat()} {fmt(i.title)}" for i in p.stale]),
    ]


def report_text(p: Plan, applied: bool) -> str:
    mode = "applied" if applied else "dry run; --apply makes these changes"
    lines = [f"{p.repo}: {p.tasks} board tasks, {p.issues} issues ({mode})", ""]
    lines.append(f"Labels to create ({len(p.create_labels)}):")
    lines += [f"  {n}" for n in p.create_labels] or ["  none"]
    lines.append(f"Issue changes ({len(p.changes)}):")
    for c in p.changes:
        lines.append("  " + change_line(c))
        if c.comment:
            lines.append(f"    comment: {c.comment}")
    if not p.changes:
        lines.append("  none")
    lines.append("")
    lines.append("Drift report:")
    for head, items in drift_sections(p, clean):
        lines.append(f"  {head} ({len(items)}):")
        lines += [f"    {x}" for x in items] or ["    none"]
    return "\n".join(lines) + "\n"


def report_markdown(p: Plan, applied: bool) -> str:
    mode = "applied" if applied else "dry run"
    lines = [f"## Issue hygiene ({mode})", "",
             f"{p.tasks} board tasks, {p.issues} issues in `{p.repo}`. "
             f"{len(p.changes)} issue changes, {len(p.create_labels)} labels created.", ""]
    if p.changes:
        lines += ["### Changes", ""] + [f"- {change_line(c)}" for c in p.changes] + [""]
    lines += ["### Drift", ""]
    for head, items in drift_sections(p, md):
        lines.append(f"**{head}** ({len(items)})")
        lines.append("")
        lines += [f"- {x}" for x in items] or ["- none"]
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str], gh_factory=GitHub, now: dt.datetime | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apply", action="store_true", help="make the changes (default: dry run)")
    ap.add_argument("--repo", help="OWNER/NAME (default: $GITHUB_REPOSITORY, else gh repo view)")
    ap.add_argument("--summary", help="append the report as Markdown to this file ($GITHUB_STEP_SUMMARY)")
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding=ENCODING, errors="replace")

    tasks = load_tasks()
    label_defs = load_label_defs()
    gh = gh_factory(resolve_repo(args.repo))
    p = plan(gh.repo, tasks, gh.list_issues(), gh.list_labels(), label_defs,
             now or dt.datetime.now(dt.timezone.utc))
    if args.apply:
        apply(p, gh, label_defs)
    sys.stdout.write(report_text(p, args.apply))
    if args.summary:
        with open(args.summary, "a", encoding=ENCODING, newline="\n") as f:
            f.write(report_markdown(p, args.apply))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
