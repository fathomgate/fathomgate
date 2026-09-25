# SPDX-License-Identifier: Apache-2.0
"""tools/status/render.py writes UTF-8 with LF on every OS (T0.8)."""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

pytest.importorskip("yaml")

RENDER = pathlib.Path(__file__).resolve().parents[2] / "tools" / "status" / "render.py"


def load_render():
    spec = importlib.util.spec_from_file_location("status_render", RENDER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_status_is_utf8_with_lf(tmp_path, monkeypatch):
    render = load_render()
    out = tmp_path / "STATUS.md"
    monkeypatch.setattr(render, "STATUS", out)
    monkeypatch.setattr(render, "ROOT", tmp_path)

    assert render.main([]) == 0
    data = out.read_bytes()
    text = data.decode("utf-8")  # raises if the platform codec leaked in
    assert b"\r" not in data
    assert "—" in text  # the renderer's em dash survives as UTF-8

    assert render.main(["--check"]) == 0


def test_check_fails_on_crlf_copy(tmp_path, monkeypatch):
    render = load_render()
    out = tmp_path / "STATUS.md"
    monkeypatch.setattr(render, "STATUS", out)
    monkeypatch.setattr(render, "ROOT", tmp_path)

    assert render.main([]) == 0
    out.write_bytes(out.read_bytes().replace(b"\n", b"\r\n"))
    assert render.main(["--check"]) == 1


@pytest.mark.parametrize(
    "criterion, line",
    [
        ("Binaries on a tag", "- [ ] Binaries on a tag"),
        ({"text": "Binaries on a tag"}, "- [ ] Binaries on a tag"),
        (
            {"text": "Binaries on a tag", "met": "2026-09-23 (PR #1)"},
            "- [x] Binaries on a tag — met 2026-09-23 (PR #1)",
        ),
    ],
)
def test_exit_criterion_ticks_only_when_met(criterion, line):
    assert load_render().criterion_line(criterion) == line
