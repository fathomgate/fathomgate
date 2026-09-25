# SPDX-License-Identifier: FSL-1.1-ALv2
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


@pytest.mark.parametrize(
    "name, parsed",
    [
        # The board's form (M1-31): a hyphen in the task id.
        (
            "2026-09-26-mcp-protocol-engineer-to-go-reviewer-M1-06.md",
            ("2026-09-26", "mcp-protocol-engineer", "go-reviewer", "M1-06"),
        ),
        (
            "2026-09-26-docs-writer-to-test-engineer-M1-31.md",
            ("2026-09-26", "docs-writer", "test-engineer", "M1-31"),
        ),
        (
            "2026-09-26-mcp-protocol-engineer-to-security-reviewer-M1-06-round2.md",
            ("2026-09-26", "mcp-protocol-engineer", "security-reviewer", "M1-06"),
        ),
        (
            "2026-09-26-test-engineer-to-go-reviewer-T0-5.md",
            ("2026-09-26", "test-engineer", "go-reviewer", "T0-5"),
        ),
        # The dot form every earlier note uses parses as before.
        (
            "2026-09-25-test-engineer-to-go-reviewer-M1.23.md",
            ("2026-09-25", "test-engineer", "go-reviewer", "M1.23"),
        ),
        (
            "2026-09-25-test-engineer-to-security-reviewer-T0.51.md",
            ("2026-09-25", "test-engineer", "security-reviewer", "T0.51"),
        ),
        (
            "2026-09-25-orchestrator-to-joshscott13-M1.md",
            ("2026-09-25", "orchestrator", "joshscott13", "M1"),
        ),
        (
            "2026-09-23-joshscott13-to-netguard-orchestrator-M0.md",
            ("2026-09-23", "joshscott13", "netguard-orchestrator", "M0"),
        ),
        ("README.md", None),
        ("_template.md", None),
    ],
)
def test_handoff_name_accepts_hyphen_and_dot_task_ids(name, parsed):
    assert load_render().parse_handoff_name(name) == parsed


def test_every_existing_note_parses_as_the_dot_only_pattern_did():
    render = load_render()
    for p in sorted(render.HANDOFFS.glob("*.md")):
        m = render.HANDOFF_RE.match(p.name)
        assert render.parse_handoff_name(p.name) == (m.groups() if m else None), p.name


def test_latest_handoffs_lists_a_hyphen_id_note(tmp_path, monkeypatch):
    render = load_render()
    notes = tmp_path / "handoffs"
    notes.mkdir()
    (notes / "2026-09-26-mcp-protocol-engineer-to-go-reviewer-M1-06.md").write_text(
        "# M1-06: dual-era handshake ready for review\n", encoding="utf-8"
    )
    (notes / "2026-09-25-test-engineer-to-go-reviewer-M1.23.md").write_text(
        "# M1.23: older note\n", encoding="utf-8"
    )
    monkeypatch.setattr(render, "HANDOFFS", notes)

    got = render.latest_handoffs()
    assert [(d, f, t, k) for d, f, t, k, _, _ in got] == [
        ("2026-09-26", "mcp-protocol-engineer", "go-reviewer", "M1-06"),
        ("2026-09-25", "test-engineer", "go-reviewer", "M1.23"),
    ]
    assert got[0][5] == "M1-06: dual-era handshake ready for review"
