# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2: `tools/list` and `tools/call` pass through `fathomgate serve` to the
real upstream krisiasty/netdev-ssh-mcp (pinned in conftest), which reaches
the fake SSH device.

Matrix row 1 (`tools/list` passes through with server prefix) and the
client half of M0 exit criterion 2. The client here is the python-sdk, not
Claude Code or Cursor; see docs/testing/test-matrix.md row 22 for what a
human still checks in a real client.

The M1 cases at the bottom (audit event, `deny` with rule id) stay skipped
until the pipeline is wired at `Proxy.dispatch` (ADR 0012).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path

import pytest
import yaml

from .conftest import REPO, SERVER, FakeDevice, RawClient, client_env, serve_args

pytestmark = [pytest.mark.tier2, pytest.mark.netdev_ssh_mcp]

# The upstream's full tool set at the pinned version. Equality, not subset:
# a new or renamed upstream tool is the drift signal for the profile.
UPSTREAM_TOOLS = {"get_config", "run_ping", "run_show_command", "run_traceroute", "trust_host_key"}


def _text(result) -> str:
    return "".join(getattr(c, "text", "") or "" for c in result.content)


@pytest.mark.asyncio
async def test_tools_list_passes_through_with_prefix(proxy_server_params: dict) -> None:
    """Row 1: every upstream tool appears once as `netdev-ssh-mcp.<tool>`."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "fathomgate"
            tools = (await session.list_tools()).tools

    names = [t.name for t in tools]
    assert sorted(names) == sorted(f"{SERVER}.{t}" for t in UPSTREAM_TOOLS)
    # Claude Code exposes `mcp__<config key>__<tool>` with `.` turned into `_`
    # (seen with Claude Code 2.1.236: `mcp__netdev__netdev-ssh-mcp_run_show_command`),
    # and model APIs cap tool names at 64 characters. Keep the prefixed names
    # short enough that even a config key of `netdev-ssh-mcp` fits.
    assert all(len(f"mcp__{SERVER}__{n}") <= 64 for n in names)
    show = next(t for t in tools if t.name == f"{SERVER}.run_show_command")
    assert {"host", "command", "port"} <= set(show.input_schema["required"])


def test_upstream_negotiates_2026_07_28_stateless(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> None:
    """Row 2, the 2026-era half (the 2025-era half is test_upa_netmiko.py):
    fathomgate's `server/discover` succeeds against netdev-ssh-mcp (go-sdk), so
    it logs `upstream ready ... protocol=2026-07-28 era=stateless`, and a
    2025-11-25 agent still initialises in front of it."""
    client = RawClient([str(fathomgate_binary), *serve_args(upstream_binary, fake_device)], client_env(dict(os.environ)))
    try:
        init = client.initialize()
        assert init["result"]["protocolVersion"] == "2025-11-25"
        # wait() -> communicate() closes stdin (the agent disconnects), so
        # fathomgate exits 0; do not close it here first (Python 3.12 then
        # raises on the flush of a closed pipe).
        code, err, _ = client.wait(timeout=20)
    finally:
        client.close()
    assert code == 0, err
    ready = [line for line in err.splitlines() if 'msg="upstream ready"' in line]
    assert len(ready) == 1, err
    assert f"server={SERVER} tools={len(UPSTREAM_TOOLS)} protocol=2026-07-28 era=stateless" in ready[0]


def test_profile_matches_upstream_tools() -> None:
    """The profile fathomgate will classify with (M1) names exactly the tools
    the pinned upstream lists."""
    profile = yaml.safe_load((REPO / "profiles" / "netdev-ssh-mcp.yaml").read_text())
    assert profile["server"] == SERVER
    assert set(profile["tools"]) == UPSTREAM_TOOLS


@pytest.mark.asyncio
async def test_show_version_reaches_device_through_proxy(proxy_server_params: dict, fake_device: FakeDevice) -> None:
    """A read-only call: `run_show_command` with `show version` runs once on
    the device and the transcript comes back unchanged (M0 forwards; no
    policy, no redaction yet)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": "show version"},
            )

    assert not result.is_error, _text(result)
    transcript = (REPO / "tests/fixtures/device/transcripts/eos/show_version.txt").read_text()
    assert _text(result).strip() == transcript.strip()
    assert fake_device.commands() == ["show version"]


# --- show running-config (T0.26) ---------------------------------------------
#
# The transcript is a real public EOS-4.16 sample with FAKE credentials
# (tests/fixtures/device/README.md). netdev-ssh-mcp refuses `show run...` in
# run_show_command ("use the get_config tool"), so this goes through
# get_config, which sends `show running-config | no-more` for EOS.
#
# netdev-ssh-mcp replaces secrets itself by default. Up to v1.6.6 the token
# was `[h:<first 6 bytes of sha256(value), hex>]`, with no key, so a
# low-entropy value such as `public` was recovered by hashing a dictionary
# (T0.29). Since v1.7.0 (GHSA-8g43-jrf3-q9vq, internal/netdev/obfuscate.go and
# obfuscation_key.go at 0869bc3) the token keeps that shape but is
# HMAC-SHA256 under a key derived from OBFUSCATION_KEY or
# --obfuscation-key-file / OBFUSCATION_KEY_FILE; with neither set the server
# draws a random key for the run and appends a notice to results that hold a
# token. It is the upstream's feature, can be switched off with
# --no-obfuscate, and is not fathomgate's redaction (invariant 4 applies to
# fathomgate's own tokens; row 15). In M0 fathomgate redacts nothing, so with
# --no-obfuscate the agent sees the config exactly as the device sent it.

RUNNING_CONFIG = REPO / "tests/fixtures/device/transcripts/eos/show_running_config.txt"
RUNNING_CONFIG_SECRETS: list[str] = json.loads((REPO / "tests/fixtures/configs/eos-4.16.expect.json").read_text())["secrets"]

# A FAKE obfuscation key for the upstream, handed over by the optional route
# docs/install.md describes: a key file, `--upstream-env OBFUSCATION_KEY_FILE=<path>`.
UPSTREAM_OBFUSCATION_KEY = "FAKE-netdev-ssh-mcp-obfuscation-key-0123456789"
# The upstream's domain-separation label (obfuscate.go, obfuscationKeyLabel).
UPSTREAM_OBFUSCATION_LABEL = b"netdev-ssh-mcp/obfuscation/v1"
UPSTREAM_TOKEN = re.compile(r"\[h:[0-9a-f]{12}\]")
# EphemeralKeyNotice's opening words (obfuscation_key.go). Upstream text is
# data: the test compares it and never acts on it.
UPSTREAM_EPHEMERAL_NOTICE = "Note from netdev-ssh-mcp: the [h:...] tokens above use a random key"


def _upstream_token(secret: str, key: str) -> str:
    """netdev-ssh-mcp v1.7.x hashSecret: HMAC-SHA256(k, value) cut to 48 bits,
    where k = HMAC-SHA256(key, label) (SetObfuscationKey)."""
    k = hmac.new(key.strip().encode(), UPSTREAM_OBFUSCATION_LABEL, hashlib.sha256).digest()
    return f"[h:{hmac.new(k, secret.encode(), hashlib.sha256).digest()[:6].hex()}]"


def _unkeyed_hash(secret: str) -> str:
    """netdev-ssh-mcp v1.6.6 hashSecret: unkeyed, 48 bits. Kept to prove the
    pinned upstream no longer produces it."""
    return f"[h:{hashlib.sha256(secret.encode()).digest()[:6].hex()}]"


async def _get_running_config_with_init(params: dict, port: int):
    """The agent's initialize result and the get_config result."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**params)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            return init, await session.call_tool(
                f"{SERVER}.get_config",
                {"host": "127.0.0.1", "port": port, "device_type": "eos", "config_type": "running"},
            )


async def _get_running_config(params: dict, port: int):
    return (await _get_running_config_with_init(params, port))[1]


@pytest.fixture
def no_obfuscate_params(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> dict:
    """fathomgate serve with the upstream's own secret hashing switched off."""
    return {"command": str(fathomgate_binary), "args": serve_args(upstream_binary, fake_device, "--", "--no-obfuscate"), "env": client_env()}


@pytest.fixture
def keyed_params(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> dict:
    """fathomgate serve with the upstream's obfuscation keyed from a FAKE key
    file, the optional route in docs/install.md."""
    key_file = tmp_path / "netdev-ssh-mcp.key"
    key_file.write_text(UPSTREAM_OBFUSCATION_KEY + "\n", encoding="utf-8")
    extra = ["--upstream-env", f"OBFUSCATION_KEY_FILE={key_file}"]
    return {"command": str(fathomgate_binary), "args": serve_args(upstream_binary, fake_device, *extra), "env": client_env()}


@pytest.mark.asyncio
async def test_running_config_reaches_device_through_proxy(keyed_params: dict, fake_device: FakeDevice) -> None:
    """A read-config call with the upstream keyed: the device gets one
    `show running-config | no-more`; the agent gets the transcript with
    exactly the four credentials replaced by the upstream's keyed `[h:...]`
    token, in one content block. fathomgate changed nothing; the replacement
    is the upstream's."""
    result = await _get_running_config(keyed_params, fake_device.port)

    assert not result.is_error, _text(result)
    assert fake_device.commands() == ["show running-config | no-more"]
    assert len(result.content) == 1, _text(result)
    expected = RUNNING_CONFIG.read_text()
    for s in RUNNING_CONFIG_SECRETS:
        assert _upstream_token(s, UPSTREAM_OBFUSCATION_KEY) != _unkeyed_hash(s)
        expected = expected.replace(s, _upstream_token(s, UPSTREAM_OBFUSCATION_KEY))
    assert _text(result).strip() == expected.strip()
    changed = [a for a, b in zip(RUNNING_CONFIG.read_text().splitlines(), _text(result).splitlines(), strict=True) if a != b]
    assert len(changed) == len(RUNNING_CONFIG_SECRETS) == 4


@pytest.mark.asyncio
async def test_running_config_ephemeral_key_through_proxy(proxy_server_params: dict, fake_device: FakeDevice) -> None:
    """The upstream's default since v1.7.0, no key configured: a random key
    for the run. The four credentials become four distinct `[h:...]` tokens,
    none of them the v1.6.6 unkeyed hash, and the upstream appends its notice
    as a second content block, which fathomgate forwards as it is (M0)."""
    init, result = await _get_running_config_with_init(proxy_server_params, fake_device.port)

    assert not result.is_error, _text(result)
    assert fake_device.commands() == ["show running-config | no-more"]
    # The upstream also sets MCP `instructions` for this case
    # (EphemeralKeyInstructions); fathomgate does not relay an upstream's
    # instructions to the agent, so none of that text reaches it here.
    assert not init.instructions or "netdev-ssh-mcp" not in init.instructions, init.instructions
    assert len(result.content) == 2, _text(result)
    config, notice = result.content[0].text, result.content[1].text
    assert notice.startswith(UPSTREAM_EPHEMERAL_NOTICE), notice
    for s in RUNNING_CONFIG_SECRETS:
        assert s not in config, s
        assert _unkeyed_hash(s) not in config, s
    tokens = UPSTREAM_TOKEN.findall(config)
    assert len(tokens) == len(set(tokens)) == len(RUNNING_CONFIG_SECRETS) == 4
    changed = [a for a, b in zip(RUNNING_CONFIG.read_text().splitlines(), config.splitlines(), strict=True) if a != b]
    assert len(changed) == 4


@pytest.mark.asyncio
async def test_running_config_secrets_reach_agent_in_m0(no_obfuscate_params: dict, fake_device: FakeDevice) -> None:
    """M0 fact, asserted on purpose: with the upstream's hashing off, every
    FAKE credential reaches the agent. fathomgate serve forwards the result
    untouched; its redactor is not at the serialiser yet (ROADMAP M2).
    When it is, this test fails and test_running_config_redacted_by_fathomgate
    below XPASSes; flip both in that PR."""
    result = await _get_running_config(no_obfuscate_params, fake_device.port)

    assert not result.is_error, _text(result)
    assert fake_device.commands() == ["show running-config | no-more"]
    assert _text(result).strip() == RUNNING_CONFIG.read_text().strip()
    for s in RUNNING_CONFIG_SECRETS:
        assert s in _text(result), s


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="M2 (ROADMAP: redactor at the response serialiser; matrix row 15): M0 serve forwards get_config output unredacted",
)
@pytest.mark.asyncio
async def test_running_config_redacted_by_fathomgate(no_obfuscate_params: dict, fake_device: FakeDevice) -> None:
    """Row 15 target: even with the upstream's hashing off, no FAKE credential
    reaches the agent; each is a keyed `<redacted:hmac:...>` token, the same
    four that `make fixtures-check` proves on tests/fixtures/configs/eos-4.16.txt
    (cisco-snmp-community x2, cisco-password-type x2). M2 may need a redaction
    key flag on serve; add it to no_obfuscate_params then."""
    result = await _get_running_config(no_obfuscate_params, fake_device.port)

    assert not result.is_error, _text(result)
    text = _text(result)
    for s in RUNNING_CONFIG_SECRETS:
        assert s not in text, s
    assert text.count("<redacted:hmac:") == 4


@pytest.mark.asyncio
async def test_upstream_tool_error_passes_through(proxy_server_params: dict, fake_device: FakeDevice) -> None:
    """The upstream's own refusal comes back as a tool error (isError), not a
    protocol error, and nothing reaches the device. In M0 fathomgate makes no
    decision here: this is the upstream's check, not a `deny`."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": "reload"},
            )

    assert result.is_error
    assert "must start with 'show'" in _text(result)
    assert fake_device.commands() == []


# Since v1.7.1 (GHSA-h47r-329w-6p9h, internal/netdev/command_safety.go at
# 6fc6ab0) the upstream refuses a second command smuggled into
# run_show_command and output pipes that write files. Up to v1.7.0 it checked
# only the `show` prefix and sent the whole string in one exec request.
# Each refusal substring is the upstream's own text (checkOperationalCommand
# in command_safety.go at 6fc6ab0), so a case cannot pass on an unrelated error.
@pytest.mark.parametrize(
    ("command", "refusal"),
    [
        ("show version\nreload", "command must be a single line without control characters"),
        ("show version\r\nconfigure terminal", "command must be a single line without control characters"),
        ("show version ; reload", "command must be a single command without ';'"),
        ("show version | redirect flash:FAKE.txt", "pipe '| redirect' is not allowed"),
        ("show version | tee flash:FAKE.txt", "pipe '| tee' is not allowed"),
        ("show version > flash:FAKE.txt", "command must not use redirection ('<' or '>')"),
    ],
    ids=["lf", "crlf", "semicolon", "pipe-redirect", "pipe-tee", "redirect"],
)
@pytest.mark.asyncio
async def test_upstream_refuses_command_injection(proxy_server_params: dict, fake_device: FakeDevice, command: str, refusal: str) -> None:
    """The upstream's refusal comes back as a tool error and nothing reaches
    the device. In M0 fathomgate forwards the call; the refusal is the
    upstream's, not a `deny`. From M1, fathomgate classifies the command
    itself and must not rely on this check (profiles/netdev-ssh-mcp.yaml)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": command},
            )

    assert result.is_error, _text(result)
    assert refusal in _text(result), _text(result)
    assert fake_device.commands() == []


# --- M1: the pipeline in Proxy.dispatch --------------------------------------

m1 = pytest.mark.skip(reason="M1-28 validates these through serve --policy; the audit file they read arrives with --audit in M4 (ADR 0027)")


@m1
@pytest.mark.asyncio
async def test_show_command_allowed_and_audited(proxy_server_params: dict, fake_device: FakeDevice, tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": "show version"},
            )
            assert not result.is_error

    audit = tmp_path / "audit.jsonl"
    events = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
    assert events[-1]["decision"] == "allow"
    assert events[-1]["rule_id"] == "reads-anywhere"
    assert events[-1]["class"] == "READ_OPERATIONAL"


@m1
@pytest.mark.asyncio
async def test_reload_denied_with_rule_id(proxy_server_params: dict, fake_device: FakeDevice, tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**proxy_server_params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": "reload"},
            )
            assert result.is_error
    # The decision word and the rule id, never a substring like "not permitted".
    # The agent-facing tool-error shape is not specified yet; M1 fixes it in
    # docs/specs and asserts it here too. M1 also adds --audit to the fixture.
    audit = tmp_path / "audit.jsonl"
    events = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
    assert events[-1]["decision"] == "deny"
    assert events[-1]["rule_id"] == "no-exec"
    assert fake_device.commands() == []
