#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write THIRD_PARTY_LICENSES/ from the modules linked into cmd/fathomgate.

Usage:
  python3 tools/licences/third_party.py            # rewrite THIRD_PARTY_LICENSES/
  python3 tools/licences/third_party.py --check    # exit 1 if it is stale (CI)

On Windows use `python`; `python3` there is a Microsoft Store alias.

The module list is the union of `go list -deps ./cmd/fathomgate` with
CGO_ENABLED=0 for every release target (linux, darwin, windows on amd64 and
arm64), the same build list GoReleaser links. For each module, and for the Go
standard library, every LICENSE, LICENCE, COPYING, NOTICE or PATENTS file at
the module root is copied to THIRD_PARTY_LICENSES/<module path>/, with CRLF
turned into LF, and THIRD_PARTY_LICENSES/README.md indexes them (ADR 0020).

Module versions are not written: a version bump that leaves the licence text
unchanged does not make the folder stale, while a new module, a dropped module
or a changed licence text does. The exact versions in a binary are in its
build info (`go version -m fathomgate`).

The script fails if a module has no licence file, if its licence is not one
it recognises, if that licence is not on the allow-list below, or if NOTICE
does not name the module. Each of those needs a person, not a regenerate.
Standard library only; needs `go` on PATH and the modules in the module cache
(`go mod download`).
"""
from __future__ import annotations

import filecmp
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "THIRD_PARTY_LICENSES"
NOTICE = ROOT / "NOTICE"
MAIN_PKG = "./cmd/fathomgate"

# The release targets in .goreleaser.yaml (builds.goos x builds.goarch).
TARGETS = [(o, a) for o in ("linux", "darwin", "windows") for a in ("amd64", "arm64")]

LICENCE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|PATENTS)([.-].*)?$", re.IGNORECASE)

# Licences compatible with distributing the binary under Apache-2.0. A module
# under anything else fails the run until someone decides (and records) what
# to do about it.
ALLOWED = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC"}

STDLIB = "Go standard library"
STDLIB_DIR = "go"  # folder name under THIRD_PARTY_LICENSES/


def identify(text: str) -> list[str]:
    """Return the SPDX ids whose text appears in a licence file, in a fixed order."""
    t = " ".join(text.split())
    found = []
    if "Apache License" in t and "Version 2.0" in t:
        found.append("Apache-2.0")
    if "Permission is hereby granted, free of charge" in t:
        found.append("MIT")
    if "Redistribution and use in source and binary forms" in t:
        found.append("BSD-3-Clause" if "Neither the name" in t or "names of its contributors" in t else "BSD-2-Clause")
    if "Permission to use, copy, modify, and/or distribute this software" in t:
        found.append("ISC")
    return found


def go(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["go", *args], cwd=ROOT, env=env, check=True, capture_output=True, text=True
    ).stdout


def modules() -> dict[str, pathlib.Path]:
    """Module path -> module directory for every non-main module linked in."""
    fmt = "{{with .Module}}{{if not .Main}}{{.Path}}\t{{with .Replace}}{{.Dir}}{{else}}{{.Dir}}{{end}}{{end}}{{end}}"
    mods: dict[str, pathlib.Path] = {}
    for goos, goarch in TARGETS:
        env = dict(os.environ, CGO_ENABLED="0", GOOS=goos, GOARCH=goarch, GOFLAGS="-mod=readonly")
        for line in go("list", "-deps", "-f", fmt, MAIN_PKG, env=env).splitlines():
            if not line.strip():
                continue
            path, _, d = line.partition("\t")
            if not d:
                sys.exit(f"third_party.py: {path} is not in the module cache; run `go mod download`")
            mods[path] = pathlib.Path(d)
    return mods


def licence_files(d: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in d.iterdir() if p.is_file() and LICENCE_FILE.match(p.name))


def render(dest: pathlib.Path) -> list[str]:
    """Write the folder into dest. Returns a list of problems for a person."""
    problems: list[str] = []
    mods = modules()
    goroot = pathlib.Path(go("env", "GOROOT").strip())
    entries = [(STDLIB, STDLIB_DIR, goroot)] + [(m, m, mods[m]) for m in sorted(mods)]

    rows = []
    for name, folder, src in entries:
        files = licence_files(src)
        if not files:
            problems.append(f"{name}: no licence file in {src}")
            continue
        ids: list[str] = []
        for f in files:
            text = f.read_bytes().replace(b"\r\n", b"\n")
            target = dest / folder / f.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(text)
            for i in identify(text.decode("utf-8", errors="replace")):
                if i not in ids:
                    ids.append(i)
        if not ids:
            problems.append(f"{name}: licence not recognised in {', '.join(f.name for f in files)}; read it")
        for i in ids:
            if i not in ALLOWED:
                problems.append(f"{name}: {i} is not on the allow-list in tools/licences/third_party.py")
        spdx = " AND ".join(ids) if ids else "unrecognised"
        links = ", ".join(f"[{f.name}]({folder}/{f.name})" for f in files)
        shown = name if name == STDLIB else f"`{name}`"
        rows.append(f"| {shown} | {spdx} | {links} |")

    index = [
        "# Third-party licences",
        "",
        "The licence texts of every module linked into the `fathomgate` binary, for linux, darwin and windows on amd64 and arm64. "
        "Generated by `make licences` (`tools/licences/third_party.py`); do not edit by hand. "
        "Fathomgate itself is under the Apache License 2.0 in `LICENSE`; attributions are in `NOTICE`. "
        "Exact module versions are in the binary's build info: `go version -m fathomgate`.",
        "",
        "| Module | Licence (SPDX) | Files |",
        "| --- | --- | --- |",
        *rows,
        "",
    ]
    (dest / "README.md").write_bytes("\n".join(index).encode("utf-8"))

    notice = NOTICE.read_text(encoding="utf-8") if NOTICE.exists() else ""
    for name, _, _ in entries:
        if name not in notice:
            problems.append(f"NOTICE does not name {name}; add its attribution")
    return problems


def same_tree(a: pathlib.Path, b: pathlib.Path) -> list[str]:
    diffs: list[str] = []
    fa = {p.relative_to(a).as_posix() for p in a.rglob("*") if p.is_file()}
    fb = {p.relative_to(b).as_posix() for p in b.rglob("*") if p.is_file()}
    diffs += [f"missing {p}" for p in sorted(fa - fb)]
    diffs += [f"extra {p}" for p in sorted(fb - fa)]
    diffs += [f"differs {p}" for p in sorted(fa & fb) if not filecmp.cmp(a / p, b / p, shallow=False)]
    return diffs


def main(argv: list[str]) -> int:
    check = "--check" in argv
    with tempfile.TemporaryDirectory() as tmp:
        fresh = pathlib.Path(tmp) / "THIRD_PARTY_LICENSES"
        fresh.mkdir()
        problems = render(fresh)
        for p in problems:
            print(f"third_party.py: {p}", file=sys.stderr)
        if check:
            diffs = same_tree(fresh, OUT) if OUT.exists() else ["THIRD_PARTY_LICENSES/ does not exist"]
            for d in diffs:
                print(f"THIRD_PARTY_LICENSES is stale: {d}", file=sys.stderr)
            if diffs:
                print("run `make licences` and commit the result", file=sys.stderr)
            return 1 if diffs or problems else 0
        if OUT.exists():
            shutil.rmtree(OUT)
        shutil.copytree(fresh, OUT)
    print(f"wrote {OUT.relative_to(ROOT).as_posix()}/")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
