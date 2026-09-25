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


def test_no_note_before_m1_31_is_read_as_hyphen_form():
    # The hyphen form is tried first, so a note named before M1-31 (all dated
    # before 2026-09-25 or on it) that matched it would render differently.
    # None does: every on-disk match is a note written from M1-31 on.
    render = load_render()
    matches = [p.name for p in render.HANDOFFS.glob("*.md") if render.HANDOFF_HYPHEN_RE.match(p.name)]
    assert matches, "the M1-31 note itself is named with a hyphenated id"
    for name in matches:
        assert name[:10] >= "2026-09-25", name


def test_latest_handoffs_lists_rounds_in_order(tmp_path, monkeypatch):
    render = load_render()
    notes = tmp_path / "handoffs"
    notes.mkdir()
    names = [
        "2026-09-25-a-to-b-M1-06.md",
        "2026-09-25-a-to-b-M1-06-round2.md",
        "2026-09-25-a-to-b-M1-06-round10.md",
        "2026-09-25-a-to-b-M1.36.md",
        "2026-09-25-a-to-b-M1.36-round2.md",
        "2026-09-26-a-to-b-M1-07.md",
    ]
    for n in names:
        (notes / n).write_text("# " + n + "\n", encoding="utf-8")
    monkeypatch.setattr(render, "HANDOFFS", notes)

    got = [path.rsplit("/", 1)[1] for _, _, _, _, path, _ in render.latest_handoffs(n=10)]
    assert got == [
        "2026-09-26-a-to-b-M1-07.md",
        "2026-09-25-a-to-b-M1.36-round2.md",
        "2026-09-25-a-to-b-M1.36.md",
        "2026-09-25-a-to-b-M1-06-round10.md",
        "2026-09-25-a-to-b-M1-06-round2.md",
        "2026-09-25-a-to-b-M1-06.md",
    ]


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
