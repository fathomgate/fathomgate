# SPDX-License-Identifier: FSL-1.1-ALv2
"""tools/status/issues.py mirrors the board onto GitHub issues (M1-38). GitHub is faked."""
from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import sys

import pytest

pytest.importorskip("yaml")

ROOT = pathlib.Path(__file__).resolve().parents[2]
ISSUES = ROOT / "tools" / "status" / "issues.py"
NOW = dt.datetime(2026, 9, 25, 12, 0, tzinfo=dt.timezone.utc)
RECENT = NOW - dt.timedelta(days=1)


def load():
    spec = importlib.util.spec_from_file_location("status_issues", ISSUES)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up by name
    spec.loader.exec_module(mod)
    return mod


ig = load()

BOARD_M0 = """\
milestone: M0
title: Pass-through
tasks:
  - id: T0.1
    title: Merged task
    package: go.mod
    owner: mcp-protocol-engineer
    state: merged
    notes: 'Reviewed in PR #9. Merged in PR #14 (3147f2c) 2026-09-23.'
  - id: T0.2
    title: Dropped task
    package: x
    owner: release-engineer
    state: dropped
    notes: 'Superseded, see PR #30.'
"""

BOARD_M1 = """\
milestone: M1
title: Classify
tasks:
  - id: M1-01
    title: Blocked by the next task
    package: x
    owner: policy-engineer
    state: open
    blocked_by: [M1-02]
  - id: M1-02
    title: In review
    package: x
    owner: orchestrator
    state: in review
  - id: M1-03
    title: Validated, no PR in notes
    package: x
    owner: test-engineer
    state: validated
    notes: 'no pull request named'
  - id: M1-04
    title: Owned by a human
    package: docs/adr
    owner: joshscott13
    state: open
  - id: M1-05
    title: Nobody opened an issue
    package: x
    owner: docs-writer
    state: in progress
"""

LABEL_DEFS = {n: {"name": n, "color": "123456"} for n in [
    "milestone:M0", "milestone:M1", "state:open", "state:blocked", "state:in progress",
    "state:in review", "state:merged", "state:validated", "state:dropped",
    "agent:orchestrator", "agent:mcp-protocol-engineer", "agent:policy-engineer",
    "agent:release-engineer", "agent:test-engineer", "agent:docs-writer"]}


def issue(number, title, labels=(), state="open", updated=RECENT, assoc="MEMBER"):
    return ig.Issue(number=number, title=title, state=state, labels=tuple(labels),
                    updated_at=updated, author_association=assoc)


class FakeGitHub:
    """Records calls and applies them to its own issue list, like GitHub would."""

    def __init__(self, repo, issues, labels):
        self.repo = repo
        self.issues = {i.number: i for i in issues}
        self.labels = set(labels)
        self.calls = []
        self.comments = {}

    def list_issues(self):
        return list(self.issues.values())

    def list_labels(self):
        return set(self.labels)

    def create_label(self, name, color, description):
        self.calls.append(("create_label", name, color))
        self.labels.add(name)

    def _set(self, n, **kw):
        self.issues[n] = ig.dataclasses.replace(self.issues[n], **kw)

    def add_labels(self, n, labels):
        self.calls.append(("add", n, tuple(labels)))
        assert set(labels) <= self.labels, "label must exist before it is added"
        self._set(n, labels=tuple(dict.fromkeys(self.issues[n].labels + tuple(labels))))

    def remove_label(self, n, label):
        self.calls.append(("remove", n, label))
        self._set(n, labels=tuple(x for x in self.issues[n].labels if x != label))

    def close(self, n, reason):
        self.calls.append(("close", n, reason))
        self._set(n, state="closed", state_reason=reason)

    def comment(self, n, body):
        self.calls.append(("comment", n, body))
        self.comments.setdefault(n, []).append(body)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    ms = tmp_path / "docs" / "milestones"
    ms.mkdir(parents=True)
    (ms / "M0.yaml").write_text(BOARD_M0, encoding="utf-8")
    (ms / "M1.yaml").write_text(BOARD_M1, encoding="utf-8")
    labels = tmp_path / "labels.yml"
    labels.write_text("".join(f"- name: \"{n}\"\n  color: \"123456\"\n" for n in LABEL_DEFS), encoding="utf-8")
    monkeypatch.setattr(ig, "MILESTONES", ms)
    monkeypatch.setattr(ig, "LABELS_YML", labels)
    return tmp_path


def live_issues():
    return [
        issue(1, "T0.1 Merged task", ["milestone:M0", "state:in review", "agent:mcp-protocol-engineer"]),
        issue(2, "T0.2 Dropped task", ["milestone:M0", "state:open", "agent:release-engineer"]),
        issue(3, "M1-01 Blocked by the next task", ["milestone:M1", "state:open", "agent:policy-engineer"]),
        issue(4, "M1-02 In review", ["milestone:M1", "state:in review", "agent:netguard-orchestrator"]),
        issue(5, "M1-03: Validated, no PR in notes", ["milestone:M1", "state:merged"]),
        issue(6, "M1-04 Owned by a human", ["milestone:M1", "state:open", "agent:docs-writer"]),
        issue(7, "M1-99 Not on any board", ["state:open"]),
        issue(8, "Share a sample config", ["help wanted"], updated=NOW - dt.timedelta(days=45)),
        issue(9, "M1-02 Spoofed by an outsider", [], assoc="NONE"),
        issue(10, "M1-0x is not a task id prefix", []),
        issue(11, "T0.1 Merged task (old copy)", ["milestone:M0", "state:merged", "agent:mcp-protocol-engineer"],
              state="closed", updated=NOW - dt.timedelta(days=90)),
    ]


def fake(issues=None, labels=None):
    return FakeGitHub("o/r", live_issues() if issues is None else issues,
                      set(LABEL_DEFS) - {"agent:orchestrator"} | {"agent:netguard-orchestrator", "help wanted"}
                      if labels is None else labels)


def make_plan(gh):
    return ig.plan(gh.repo, ig.load_tasks(), gh.list_issues(), gh.list_labels(), ig.load_label_defs(), NOW)


def change(p, n):
    return next((c for c in p.changes if c.issue.number == n), None)


def test_task_id_prefix():
    assert ig.task_id("M1-22 Tier 2 harness") == "M1-22"
    assert ig.task_id("T0.14 Move the build toolchain") == "T0.14"
    assert ig.task_id("M1-03: colon") == "M1-03"
    assert ig.task_id("M1-38") == "M1-38"
    assert ig.task_id("M1-0x not an id") is None
    assert ig.task_id("Fix M1-22 later") is None
    assert ig.task_id("T0.1x") is None


@pytest.mark.parametrize("notes, pr", [
    ("Reviewed in PR #9. Merged in PR #14 (3147f2c).", 14),
    ("Merged in #20", 20),
    ("From the review of PR #154; recorded in PR #153.", 153),
    ("no pull request", None),
])
def test_pr_of(notes, pr):
    assert ig.pr_of(notes) == pr


def test_labels_follow_board(repo):
    p = make_plan(fake())
    # merged task: state label corrected, closed as completed, comment names the merging PR
    c = change(p, 1)
    assert c.add == ["state:merged"] and c.remove == ["state:in review"]
    assert c.close_reason == "completed"
    assert c.comment == "T0.1 is `merged` on the board (docs/milestones/M0.yaml, PR #14); closed by tools/status/issues.py."
    # an open task whose blocker is not merged is blocked, as STATUS.md shows it
    c = change(p, 3)
    assert c.add == ["state:blocked"] and c.remove == ["state:open"] and c.close_reason is None
    # the legacy agent label goes, the owner's label comes (and must be created)
    c = change(p, 4)
    assert c.add == ["agent:orchestrator"] and c.remove == ["agent:netguard-orchestrator"]
    assert p.create_labels == ["agent:orchestrator"]
    # a human owner's issue keeps its agent labels; it is reported
    assert change(p, 6) is None
    assert [(i.number, t.id) for i, t in p.human_owner] == [(6, "M1-04")]


def test_close_reasons_and_comments(repo):
    p = make_plan(fake())
    assert change(p, 2).close_reason == "not_planned"
    assert "PR #30" in change(p, 2).comment
    c = change(p, 5)
    assert c.close_reason == "completed"
    assert c.add == ["agent:test-engineer", "state:validated"] and c.remove == ["state:merged"]
    assert "PR #" not in c.comment
    assert "\n" not in c.comment


def test_untrusted_and_unprefixed_issues_untouched(repo):
    gh = fake()
    p = make_plan(gh)
    touched = {c.issue.number for c in p.changes}
    assert 9 not in touched and 7 not in touched and 8 not in touched and 10 not in touched
    assert [i.number for i in p.untrusted] == [9]
    ig.apply(p, gh, ig.load_label_defs())
    assert all(call[1] not in (7, 8, 9, 10) for call in gh.calls if call[0] != "create_label")


def test_drift_report(repo):
    p = make_plan(fake())
    assert [i.number for i in p.unknown_task] == [7]
    assert [t.id for t in p.missing_issue] == ["M1-05"]
    assert [i.number for i in p.stale] == [8]
    assert [(t.id, [i.number for i in lst]) for t, lst in p.duplicates] == [("T0.1", [1, 11])]
    text = ig.report_text(p, applied=False)
    assert "dry run" in text and "M1-05" in text and "#8 last updated 2026-08-11" in text


def test_closed_issue_of_active_task_is_reported_not_reopened(repo):
    gh = fake([issue(3, "M1-01 Blocked by the next task", ["milestone:M1", "state:blocked", "agent:policy-engineer"],
                     state="closed")])
    p = make_plan(gh)
    assert [(i.number, t.id) for i, t in p.closed_active] == [(3, "M1-01")]
    assert p.changes == []


def test_closed_issue_labels_are_still_corrected(repo):
    gh = fake([issue(1, "T0.1 Merged task", ["milestone:M0", "state:open", "agent:mcp-protocol-engineer"],
                     state="closed")])
    c = change(make_plan(gh), 1)
    assert c.add == ["state:merged"] and c.close_reason is None and c.comment is None


def test_dry_run_changes_nothing(repo, capsys):
    gh = fake()
    before = dict(gh.issues)
    assert ig.main([], gh_factory=lambda r: gh, now=NOW) == 0
    assert gh.calls == [] and gh.issues == before
    out = capsys.readouterr().out
    assert "dry run" in out and "#1 T0.1 (merged): add state:merged; remove state:in review; close as completed" in out


def test_apply_is_idempotent(repo, tmp_path, capsys):
    gh = fake()
    summary = tmp_path / "summary.md"
    assert ig.main(["--apply", "--repo", "o/r", "--summary", str(summary)], gh_factory=lambda r: gh, now=NOW) == 0
    first = list(gh.calls)
    assert ("create_label", "agent:orchestrator", "123456") in first
    assert ("close", 2, "not_planned") in first
    assert first.index(("close", 1, "completed")) < first.index(next(c for c in first if c[:2] == ("comment", 1)))
    assert gh.issues[1].state == "closed" and set(gh.issues[1].labels) == {
        "milestone:M0", "state:merged", "agent:mcp-protocol-engineer"}
    # every trusted task issue now carries exactly one state: label
    for n in (1, 2, 3, 4, 5, 6):
        assert sum(label.startswith("state:") for label in gh.issues[n].labels) == 1
    md = summary.read_text(encoding="utf-8")
    assert md.startswith("## Issue hygiene (applied)") and "### Drift" in md

    gh.calls.clear()
    assert ig.main(["--apply", "--repo", "o/r"], gh_factory=lambda r: gh, now=NOW) == 0
    assert gh.calls == []
    assert len(gh.comments[1]) == 1
    assert "Issue changes (0):" in capsys.readouterr().out


def test_untrusted_title_is_escaped():
    t = "M1-99 ::add-mask::x\r\n| <img src=x> [a](b)"
    assert "\n" not in ig.clean(t) and "\r" not in ig.clean(t)
    m = ig.md(t)
    assert "\\|" in m and "\\<img" in m and "\\[a\\]" in m


def test_live_board_loads():
    tasks = ig.load_tasks()
    ids = [t.id for t in tasks]
    assert len(ids) == len(set(ids))
    assert all(ig.task_id(f"{i} title") == i for i in ids), "every board id must match TASK_ID_RE"
    defs = ig.load_label_defs()
    assert all(f"state:{s}" in defs for s in ig.render.STATES)


def test_gh_api_calls(monkeypatch):
    seen = []

    class R:
        returncode = 0
        stdout = '{"number": 3, "title": "M1-01 x", "state": "open", "state_reason": null, ' \
                 '"updated_at": "2026-09-25T20:25:21Z", "author_association": "MEMBER", "labels": ["state:open"]}\n'
        stderr = ""

    def run(cmd, **kw):
        seen.append((cmd, kw.get("input")))
        return R()

    monkeypatch.setattr(ig.subprocess, "run", run)
    gh = ig.GitHub("o/r")
    [i] = gh.list_issues()
    assert i.number == 3 and i.labels == ("state:open",) and i.updated_at.tzinfo is not None
    assert "--paginate" in seen[0][0] and "repos/o/r/issues?state=all&per_page=100" in seen[0][0]
    gh.remove_label(3, "state:in progress")
    assert seen[-1][0][-1] == "repos/o/r/issues/3/labels/state%3Ain%20progress"
    gh.close(3, "not_planned")
    assert '"state_reason": "not_planned"' in seen[-1][1]
