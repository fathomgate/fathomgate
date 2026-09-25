# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2: `fathomgate serve --policy` over stdio in front of the real
netdev-ssh-mcp and the fake device (M1-20; M2 in the security review of
PR #171).

`serve --policy policies/examples/read-only.yaml --inventory <file listing the
fake device>` with the embedded profiles: `show version` is forwarded and runs
on the device; `reload` is denied by `no-exec`; a host not in the inventory
(`localhost`, which reaches the same fake device, and `10.99.99.99`) is denied
by `default:unknown_target`. The device's session log proves the denied calls
opened no SSH session, and its command log that nothing ran.

This is gated coverage in CI, not the M1-28 validation of matrix rows 3, 4
and 6, which also runs upa and eos-mcp and records run ids.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import REPO, SERVER, FakeDevice, client_env, owner_only_file, serve_args

pytestmark = [pytest.mark.tier2, pytest.mark.netdev_ssh_mcp]

# The no-exec reason of the example policies (PR #170).
NO_EXEC = "EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"


def _text(result) -> str:
    return "\n".join(getattr(c, "text", "") for c in result.content)


@pytest.mark.asyncio
async def test_policy_read_only_over_stdio(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    policy = owner_only_file(tmp_path / "read-only.yaml", (REPO / "policies/examples/read-only.yaml").read_text(encoding="utf-8"))
    inventory = owner_only_file(tmp_path / "inventory.yaml", "devices:\n  - name: 127.0.0.1\n    role: lab\n    tags: [lab]\n")
    args = [a for a in serve_args(upstream_binary, fake_device) if a != "--no-policy"]
    args += ["--policy", str(policy), "--inventory", str(inventory)]
    params = StdioServerParameters(command=str(fathomgate_binary), args=args, env=client_env())
    common = {"port": fake_device.port, "device_type": "eos"}
    tool = f"{SERVER}.run_show_command"

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            allowed = await session.call_tool(tool, {"host": "127.0.0.1", "command": "show version", **common})
            assert not allowed.is_error, _text(allowed)
            assert "Arista" in _text(allowed), _text(allowed)
            assert fake_device.commands() == ["show version"]
            sessions = fake_device.sessions()
            assert sessions >= 1

            reload = await session.call_tool(tool, {"host": "127.0.0.1", "command": "reload", **common})
            assert reload.is_error
            assert _text(reload) == (
                f"fathomgate denied {tool}: rule no-exec (class EXEC_ARBITRARY): {NO_EXEC}"
            ), _text(reload)

            for host in ("localhost", "10.99.99.99"):
                unknown = await session.call_tool(tool, {"host": host, "command": "show version", **common})
                assert unknown.is_error
                assert _text(unknown) == (
                    f"fathomgate denied {tool}: rule default:unknown_target (class READ_OPERATIONAL): target not in inventory"
                ), _text(unknown)

    # Nothing the policy denied reached the device: no new session, no command.
    assert fake_device.sessions() == sessions
    assert fake_device.commands() == ["show version"]
