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
import json
import os
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
# netdev-ssh-mcp v1.6.6 replaces secrets itself by default (internal/netdev/
# obfuscate.go): `[h:<first 6 bytes of sha256(value), hex>]`. That hash has no
# key, so a low-entropy value such as `public` is recovered by hashing a
# dictionary. It is the upstream's feature, can be switched off with
# --no-obfuscate, and is not fathomgate's redaction (keyed HMAC, invariant 4).
# In M0 fathomgate redacts nothing, so with --no-obfuscate the agent sees the
# config exactly as the device sent it.

RUNNING_CONFIG = REPO / "tests/fixtures/device/transcripts/eos/show_running_config.txt"
RUNNING_CONFIG_SECRETS: list[str] = json.loads((REPO / "tests/fixtures/configs/eos-4.16.expect.json").read_text())["secrets"]


def _upstream_hash(secret: str) -> str:
    """netdev-ssh-mcp v1.6.6 hashSecret: unkeyed, 48 bits."""
    return f"[h:{hashlib.sha256(secret.encode()).digest()[:6].hex()}]"


async def _get_running_config(params: dict, port: int):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async with stdio_client(StdioServerParameters(**params)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await session.call_tool(
                f"{SERVER}.get_config",
                {"host": "127.0.0.1", "port": port, "device_type": "eos", "config_type": "running"},
            )


@pytest.fixture
def no_obfuscate_params(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> dict:
    """fathomgate serve with the upstream's own secret hashing switched off."""
    return {"command": str(fathomgate_binary), "args": serve_args(upstream_binary, fake_device, "--", "--no-obfuscate"), "env": client_env()}


@pytest.mark.asyncio
async def test_running_config_reaches_device_through_proxy(proxy_server_params: dict, fake_device: FakeDevice) -> None:
    """A read-config call with the upstream's defaults: the device gets one
    `show running-config | no-more`; the agent gets the transcript with
    exactly the four credentials replaced by the upstream's `[h:...]` hash.
    fathomgate changed nothing; the replacement is the upstream's."""
    result = await _get_running_config(proxy_server_params, fake_device.port)

    assert not result.is_error, _text(result)
    assert fake_device.commands() == ["show running-config | no-more"]
    expected = RUNNING_CONFIG.read_text()
    for s in RUNNING_CONFIG_SECRETS:
        expected = expected.replace(s, _upstream_hash(s))
    assert _text(result).strip() == expected.strip()
    changed = [a for a, b in zip(RUNNING_CONFIG.read_text().splitlines(), _text(result).splitlines(), strict=True) if a != b]
    assert len(changed) == len(RUNNING_CONFIG_SECRETS) == 4


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


# --- M1: the pipeline in Proxy.dispatch --------------------------------------

m1 = pytest.mark.skip(reason="M1: pipeline not wired; serve refuses --policy and --audit (ADR 0012)")


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
