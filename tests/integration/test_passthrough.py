"""Tier 2: `tools/list` and `tools/call` pass through the proxy to a real
upstream (netdev-ssh-mcp) with the server prefix applied.

Skipped until M0 ships the proxy transport. The body shows the intended
shape: spawn `netguard serve` over stdio, connect an MCP client, list tools,
call a read tool, and check that the audit log recorded one allowed event.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.tier2,
    pytest.mark.skip(reason="M0: proxy transport not implemented"),
]


@pytest.mark.asyncio
async def test_tools_list_passes_through_with_prefix(proxy_server_params: dict) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(**proxy_server_params)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            # Validated against krisiasty/netdev-ssh-mcp (research brief 02 §1.1).
            assert {"netdev-ssh-mcp.get_config", "netdev-ssh-mcp.run_show_command"} <= names


@pytest.mark.asyncio
async def test_show_command_allowed_and_audited(proxy_server_params: dict, tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(**proxy_server_params)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "netdev-ssh-mcp.run_show_command",
                {"host": "lab-leaf-01", "command": "show version"},
            )
            assert not result.isError

    audit = tmp_path / "audit.jsonl"
    events = [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]
    assert events[-1]["decision"] == "allow"
    assert events[-1]["rule_id"] == "reads-anywhere"
    assert events[-1]["class"] == "READ_OPERATIONAL"


@pytest.mark.asyncio
async def test_reload_denied_with_rule_id(proxy_server_params: dict) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(**proxy_server_params)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "netdev-ssh-mcp.run_show_command",
                {"host": "lab-leaf-01", "command": "reload"},
            )
            assert result.isError
            text = "".join(getattr(c, "text", "") for c in result.content)
            # Every denial names its rule.
            assert "no-exec" in text
