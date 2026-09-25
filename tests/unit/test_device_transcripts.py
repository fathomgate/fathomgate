# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 1: the fake-device transcripts and the redaction fixtures agree.

`tests/fixtures/device/transcripts/eos/show_running_config.txt` is what the
fake device sends; `tests/fixtures/configs/eos-4.16.txt` is the same config
with a header and `! <rule-id>` annotations, which `make fixtures-check`
runs through the redactor. If one is edited without the other, the tier 2
test and the redaction test would be checking different text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.tier1

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TRANSCRIPT = FIXTURES / "device" / "transcripts" / "eos" / "show_running_config.txt"
REDACT_FIXTURE = FIXTURES / "configs" / "eos-4.16.txt"
EXPECT = FIXTURES / "configs" / "eos-4.16.expect.json"

HEADER_LINES = 4
ANNOTATION = re.compile(r"\s+! [a-z0-9-]+$")


def test_redaction_fixture_is_the_transcript() -> None:
    fixture = REDACT_FIXTURE.read_text(encoding="utf-8").splitlines()
    body = [ANNOTATION.sub("", line) for line in fixture[HEADER_LINES:]]
    assert body == TRANSCRIPT.read_text(encoding="utf-8").splitlines()


def test_every_transcript_secret_is_fake_and_listed() -> None:
    transcript = TRANSCRIPT.read_text(encoding="utf-8")
    secrets = json.loads(EXPECT.read_text(encoding="utf-8"))["secrets"]
    assert len(secrets) == 4
    for s in secrets:
        assert "FAKE" in s
        assert transcript.count(s) == 1, s
    # The published sample's values must never come back.
    for line in transcript.splitlines():
        if line.startswith("snmp-server community "):
            assert line.split()[2].startswith("FAKE-"), line
        if " secret " in line:
            assert "$1$FAKEsalt$FAKE" in line, line
