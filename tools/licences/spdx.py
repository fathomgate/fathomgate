#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that every Go, Python and shell source file carries the SPDX line.

Usage:
  python3 tools/licences/spdx.py            # exit 1 and list files without it (CI)
  python3 tools/licences/spdx.py --fix      # add it where it is missing

On Windows use `python`; `python3` there is a Microsoft Store alias.

The line is `SPDX-License-Identifier: Apache-2.0` in the file's comment syntax
(ADR 0020): `// ` for Go, `# ` for Python and shell. It is the first line, or
the second after a `#!` line. Go files get a blank line after it, so it never
becomes a package doc comment.

Files are the ones git tracks: `*.go`, `*.py`, `*.sh`, and files with no
extension whose `#!` line names python, sh or bash. Generated Go files (a
`// Code generated ... DO NOT EDIT.` line) are skipped. Data files (policies,
profiles, fixtures, Markdown) are covered by LICENSE without a header and are
never looked at. Standard library only; needs `git` on PATH.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ID = "SPDX-License-Identifier: Apache-2.0"
GENERATED = re.compile(r"^// Code generated .* DO NOT EDIT\.$", re.MULTILINE)
SHEBANG_KIND = re.compile(r"^#!.*\b(python3?|sh|bash)\b")


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


def expected(k: str) -> str:
    return ("// " if k == "go" else "# ") + ID


def has_header(lines: list[str], k: str) -> bool:
    head = lines[1:2] if lines and lines[0].startswith("#!") else lines[:1]
    return head == [expected(k)]


def add_header(text: str, k: str) -> str:
    line = expected(k)
    if k == "go":
        return f"{line}\n\n{text}"
    if text.startswith("#!"):
        first, _, rest = text.partition("\n")
        return f"{first}\n{line}\n{rest}"
    return f"{line}\n{text}"


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    missing: list[str] = []
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
        if has_header(lines, k):
            continue
        rel = path.relative_to(ROOT).as_posix()
        if fix:
            path.write_bytes(add_header(text, k).encode("utf-8"))
            print(f"added {rel}")
        else:
            missing.append(rel)
    for rel in missing:
        print(f"{rel}: missing `{ID}` on its first line (after any #! line)", file=sys.stderr)
    if missing:
        print("run `python3 tools/licences/spdx.py --fix` (ADR 0020)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
