#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Run gitleaks over git history and fail closed (M1-42).

    python3 tools/secrets/scan.py --gitleaks BIN --config .gitleaks.toml \\
        --ignore .gitleaksignore [--base SHA --head SHA] [--report-csv PATH]

With --base, the range is merge-base(base, head)..head (a pull request's
commits); without it, every commit reachable from --head (default HEAD).

What it adds to a bare `gitleaks git`:

- Both ends of the range must be commits in this repository, checked with
  `git cat-file -e` before gitleaks runs. gitleaks logs an invalid range,
  scans nothing and exits 0; this exits 2 instead.
- Backstop: if the range holds non-merge commits and gitleaks reports 0
  commits scanned (or no count at all), exit 2.
- Merge commits are scanned with `--diff-merges=first-parent`, so a secret
  added in a merge (an evil merge, a conflict resolution) is found; a plain
  `git log -p` shows no diff for a merge. gitleaks cannot parse the combined
  or remerge formats (`remerge CONFLICT` header lines hide the file).
- A first-parent diff also repeats everything the merge brought in from its
  other parents, which was scanned in the commits that introduced it (in
  this range, or on main when they landed) and may be listed there by
  fingerprint in .gitleaksignore. So a finding in a merge commit is dropped
  when its whole line is already present in the same file of one of the
  merge's other parents. A line that no parent has is kept.
- Inline `gitleaks:allow` comments are ignored (--ignore-gitleaks-allow).
- The value is never printed: gitleaks runs with --redact, and a finding is
  reported as rule, file, line, commit and fingerprint.

Exit 0: no findings. 1: findings. 2: the scan could not be trusted.
Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import tempfile
from typing import NoReturn

ANSI = re.compile(r"\x1b\[[0-9;]*m")
SCANNED = re.compile(r"(\d+) commits scanned")


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check)


def fail(msg: str) -> NoReturn:
    print(f"secrets-scan: {msg}", file=sys.stderr)
    sys.exit(2)


def is_commit(rev: str) -> bool:
    return git("cat-file", "-e", f"{rev}^{{commit}}", check=False).returncode == 0


def file_lines(rev: str, path: str) -> list[str] | None:
    r = git("show", f"{rev}:{path}", check=False)
    if r.returncode != 0:
        return None
    return [ln.rstrip("\r") for ln in r.stdout.split("\n")]


def parents(commit: str) -> list[str]:
    return git("rev-list", "--parents", "-n", "1", commit).stdout.split()[1:]


def inherited(finding: dict) -> bool:
    """True if the finding sits in a merge on a line one of the merge's
    non-first parents already has in the same file."""
    commit, path, line_no = finding.get("Commit", ""), finding["File"], finding["StartLine"]
    if not commit:
        return False
    ps = parents(commit)
    if len(ps) < 2:
        return False
    lines = file_lines(commit, path)
    if lines is None or not 0 < line_no <= len(lines):
        return False
    line = lines[line_no - 1]
    for p in ps[1:]:
        other = file_lines(p, path)
        if other is not None and line in other:
            return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--gitleaks", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--ignore", required=True, help="a .gitleaksignore file; must exist (may be empty)")
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--report-csv", default="", help="write the kept findings (rule, file, line, commit)")
    a = ap.parse_args()

    for path, what in ((a.config, "config"), (a.ignore, "ignore file")):
        if not os.path.isfile(path):
            fail(f"{what} {path} does not exist")
    if not is_commit(a.head):
        fail(f"head {a.head!r} is not a commit in this repository")
    if a.base:
        if not is_commit(a.base):
            fail(f"base {a.base!r} is not a commit in this repository (shallow clone, or a bad ref)")
        mb = git("merge-base", a.base, a.head, check=False)
        if mb.returncode != 0 or not mb.stdout.strip():
            fail(f"no merge base between {a.base} and {a.head}")
        rng = f"{mb.stdout.strip()}..{a.head}"
    else:
        rng = a.head
    non_merges = int(git("rev-list", "--count", "--no-merges", rng).stdout.strip())
    total = int(git("rev-list", "--count", rng).stdout.strip())
    print(f"secrets-scan: range {rng}: {total} commits, {non_merges} not merges")

    with tempfile.TemporaryDirectory() as tmp:
        report = os.path.join(tmp, "report.json")
        cmd = [
            a.gitleaks, "git",
            "--config", a.config,
            "--gitleaks-ignore-path", a.ignore,
            "--log-opts", f"--diff-merges=first-parent {rng}",
            "--ignore-gitleaks-allow",
            "--redact",
            "--no-banner",
            "--report-format", "json",
            "--report-path", report,
            "--exit-code", "1",
            ".",
        ]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except OSError as e:
            fail(f"cannot run gitleaks {a.gitleaks}: {e}")
        log = ANSI.sub("", r.stdout + r.stderr)
        sys.stderr.write(log)
        if r.returncode not in (0, 1):
            fail(f"gitleaks exited {r.returncode}")
        m = SCANNED.findall(log)
        if not m:
            fail("gitleaks did not report how many commits it scanned")
        scanned = int(m[-1])
        if non_merges > 0 and scanned == 0:
            fail(f"gitleaks scanned 0 commits of a range with {non_merges} non-merge commits")
        try:
            with open(report, encoding="utf-8") as f:
                findings = json.load(f) or []
        except (OSError, ValueError) as e:
            fail(f"cannot read the gitleaks report: {e}")
        if r.returncode == 0 and findings:
            fail("gitleaks exited 0 but reported findings")

    kept, dropped = [], 0
    for fd in findings:
        if inherited(fd):
            dropped += 1
        else:
            kept.append(fd)
    if dropped:
        print(f"secrets-scan: {dropped} finding(s) in merge commits are lines a merged parent already has; scanned in the commits that added them")
    for fd in kept:
        print(f"FINDING rule={fd['RuleID']} file={fd['File']}:{fd['StartLine']} commit={fd.get('Commit', '')[:12]} fingerprint={fd['Fingerprint']}")
    if a.report_csv:
        with open(a.report_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["RuleID", "File", "StartLine", "Commit"])
            for fd in kept:
                w.writerow([fd["RuleID"], fd["File"], fd["StartLine"], fd.get("Commit", "")])
    if kept:
        print(f"secrets-scan: {len(kept)} finding(s). Rotate a real secret (SECURITY.md); list a judged false positive in .gitleaksignore with its reason.")
        return 1
    print(f"secrets-scan: no findings ({scanned} commits scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
