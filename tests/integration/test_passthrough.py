"""Tier 2: `tools/list` and `tools/call` pass through `netguard serve` to the
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

import json
from pathlib import Path

import pytest
import yaml

from .conftest import REPO, SERVER, FakeDevice

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
            assert init.server_info.name == "netguard"
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


def test_profile_matches_upstream_tools() -> None:
    """The profile netguard will classify with (M1) names exactly the tools
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


@pytest.mark.asyncio
async def test_upstream_tool_error_passes_through(proxy_server_params: dict, fake_device: FakeDevice) -> None:
    """The upstream's own refusal comes back as a tool error (isError), not a
    protocol error, and nothing reaches the device. In M0 netguard makes no
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
