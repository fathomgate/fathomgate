#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Check that every Go, Python and shell source file carries the right SPDX line.

Usage:
  python3 tools/licences/spdx.py            # exit 1 and list files with a missing or wrong line (CI)
  python3 tools/licences/spdx.py --fix      # add a missing line, replace a wrong one

On Windows use `python`; `python3` there is a Microsoft Store alias.

The licence depends on the file's path (ADR 0034):

  policies/examples/, profiles/   SPDX-License-Identifier: Apache-2.0
  everything else                 SPDX-License-Identifier: FSL-1.1-ALv2

The line is in the file's comment syntax: `// ` for Go, `# ` for Python and
shell. It is the first line, or the second after a `#!` line. Go files get a
blank line after it, so it never becomes a package doc comment. A file whose
first SPDX line names another licence is reported as wrong, and `--fix`
rewrites that line in place.

Files are the ones git tracks: `*.go`, `*.py`, `*.sh`, and files with no
extension whose `#!` line names python, sh or bash. Generated Go files (a
`// Code generated ... DO NOT EDIT.` line) are skipped. Data files (policies,
profiles, fixtures, Markdown) are covered by the LICENSE of their directory
without a header and are never looked at. Code copied from another project
keeps its own licence: list it in EXCEPTIONS with its SPDX id. Standard
library only; needs `git` on PATH.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

FSL = "FSL-1.1-ALv2"
APACHE = "Apache-2.0"
# Directories that stay Apache-2.0 after the relicensing (ADR 0034 decision 1).
# Each has its own LICENSE file with the Apache-2.0 text.
APACHE_PATHS = ("policies/examples/", "profiles/")
# Files copied from another project, keyed by repository-relative path, with
# the SPDX id of their own licence. Empty today.
EXCEPTIONS: dict[str, str] = {}

PREFIX = "SPDX-License-Identifier: "
GENERATED = re.compile(r"^// Code generated .* DO NOT EDIT\.$", re.MULTILINE)
SHEBANG_KIND = re.compile(r"^#!.*\b(python3?|sh|bash)\b")


def licence_for(rel: str) -> str:
    """The SPDX id a file at repository-relative path `rel` must carry."""
    if rel in EXCEPTIONS:
        return EXCEPTIONS[rel]
    if rel.startswith(APACHE_PATHS):
        return APACHE
    return FSL


def kind(path: pathlib.Path, first: str) -> str | None:
    if path.suffix == ".go":
        return "go"
    if path.suffix == ".py":
        return "py"
    if path.suffix == ".sh":
        return "sh"
    if path.suffix == "":
        m = SHEBANG_KIND.match(first)
        if m:
            return "py" if m.group(1).startswith("python") else "sh"
    return None


def tracked() -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode("utf-8")
    return [ROOT / p for p in out.split("\0") if p]


def comment(k: str) -> str:
    return "// " if k == "go" else "# "


def expected(k: str, licence: str) -> str:
    return comment(k) + PREFIX + licence


def header_index(lines: list[str]) -> int:
    """Index of the line where the SPDX line belongs."""
    return 1 if lines and lines[0].startswith("#!") else 0


def state(lines: list[str], k: str, licence: str) -> str:
    """`ok`, `wrong` (an SPDX line naming another licence) or `missing`."""
    i = header_index(lines)
    if i >= len(lines):
        return "missing"
    line = lines[i]
    if line == expected(k, licence):
        return "ok"
    if line.startswith(comment(k) + PREFIX):
        return "wrong"
    return "missing"


def fix_header(text: str, k: str, licence: str) -> str:
    """Return `text` with the SPDX line for `licence` added or corrected."""
    want = expected(k, licence)
    lines = text.split("\n")
    i = header_index(lines)
    if state(text.splitlines(), k, licence) == "wrong":
        lines[i] = want
        return "\n".join(lines)
    if k == "go":
        return f"{want}\n\n{text}"
    if text.startswith("#!"):
        first, _, rest = text.partition("\n")
        return f"{first}\n{want}\n{rest}"
    return f"{want}\n{text}"


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    problems: list[str] = []
    for path in tracked():
        if not path.is_file():
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue
        lines = text.splitlines()
        k = kind(path, lines[0] if lines else "")
        if k is None or (k == "go" and GENERATED.search(text)):
            continue
        rel = path.relative_to(ROOT).as_posix()
        licence = licence_for(rel)
        s = state(lines, k, licence)
        if s == "ok":
            continue
        if fix:
            path.write_bytes(fix_header(text, k, licence).encode("utf-8"))
            print(f"{'corrected' if s == 'wrong' else 'added'} {rel}")
        else:
            problems.append(f"{rel}: {s} `{PREFIX}{licence}` on its first line (after any #! line)")
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        print("run `python3 tools/licences/spdx.py --fix` (ADR 0034)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
