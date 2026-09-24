"""Tier 2, matrix row 22: the PATH-stripped launcher.

GUI-launched MCP hosts (Claude Desktop, Cursor started from the Dock or
Finder) spawn servers with a minimal environment: often no PATH entries
beyond /usr/bin:/bin, sometimes none. netguard resolves a bare `--upstream`
name on *its own* PATH (exec.LookPath) and passes the upstream only an
allow-list of its environment (internal/proxy/command.go baseEnv), so:

- absolute `command` and absolute `--upstream` work with any PATH;
- a bare `--upstream` name fails at once with "executable file not found";
- an absolute launcher script that looks its interpreter up on PATH
  (`npx`, `uvx`, a `#!/bin/sh … exec tool` wrapper) fails at once with the
  upstream's own stderr line, and works when PATH is handed over with
  `--upstream-env PATH=…`.

Every failure must be a prompt exit 1 with the cause on stderr, never a
hang. Real upstream: krisiasty/netdev-ssh-mcp at the conftest pin.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from .conftest import SERVER, FakeDevice, RawClient, serve_args

pytestmark = [
    pytest.mark.tier2,
    pytest.mark.netdev_ssh_mcp,
    pytest.mark.skipif(sys.platform == "win32", reason="POSIX launcher semantics; Windows PATH/PATHEXT is a separate case"),
]

EXPECTED = sorted(f"{SERVER}.{t}" for t in ("get_config", "run_ping", "run_show_command", "run_traceroute", "trust_host_key"))
FAIL_FAST_SECONDS = 10  # startupTimeout in serve.go is 30s; a hang would show as >= 30


def _list_tools(client: RawClient) -> list[str]:
    init = client.initialize()
    assert "result" in init, init
    resp = client.request(2, "tools/list", {})
    return sorted(t["name"] for t in resp["result"]["tools"])


def _assert_fails_fast(client: RawClient) -> str:
    code, err, secs = client.wait(timeout=FAIL_FAST_SECONDS + 5)
    assert code == 1, (code, err)
    assert secs < FAIL_FAST_SECONDS, f"took {secs:.1f}s: {err}"
    assert "netguard: proxy: upstream netdev-ssh-mcp: connect:" in err, err
    return err


@pytest.mark.asyncio
async def test_empty_path_absolute_paths_serve_tools_list(netguard_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> None:
    """Row 22 as written: a Claude Desktop-style entry (absolute `command`,
    absolute `--upstream`) with PATH set to the empty string. The python-sdk
    client keeps HOME and USER, as a GUI host does."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=str(netguard_binary), args=serve_args(upstream_binary, fake_device), env={"PATH": ""})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            names = sorted(t.name for t in (await session.list_tools()).tools)
            result = await session.call_tool(
                f"{SERVER}.run_show_command",
                {"host": "127.0.0.1", "port": fake_device.port, "device_type": "eos", "command": "show version"},
            )
    assert names == EXPECTED
    assert not result.is_error
    assert fake_device.commands() == ["show version"]


def test_env_i_absolute_paths_serve_tools_list(netguard_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> None:
    """`env -i`: no PATH, no HOME at all. netdev-ssh-mcp needs a known_hosts
    path (it derives one from HOME), so SSH_KNOWN_HOSTS is passed with
    `--upstream-env`; netguard itself needs nothing from the environment."""
    client = RawClient([str(netguard_binary), *serve_args(upstream_binary, fake_device)], env={})
    try:
        assert _list_tools(client) == EXPECTED
    finally:
        client.close()


def test_env_i_without_home_fails_fast_with_upstream_reason(netguard_binary: Path, upstream_binary: Path) -> None:
    """Same, without SSH_KNOWN_HOSTS: the upstream exits at startup and its
    reason reaches stderr, labelled with the server name."""
    client = RawClient([str(netguard_binary), *serve_args(upstream_binary, None)], env={})
    err = _assert_fails_fast(client)
    assert "upstream netdev-ssh-mcp: configure ssh client:" in err


@pytest.mark.parametrize("path", ["", "/usr/bin:/bin"])
def test_bare_upstream_name_fails_fast(netguard_binary: Path, upstream_binary: Path, path: str) -> None:
    """A bare `--upstream netdev-ssh-mcp` with a stripped PATH: exit 1 and
    "executable file not found in $PATH", before any handshake."""
    env = {"PATH": path} if path else {}
    client = RawClient([str(netguard_binary), *serve_args(SERVER, None)], env=env)
    err = _assert_fails_fast(client)
    assert 'exec: "netdev-ssh-mcp": executable file not found in $PATH' in err


def _launcher(tmp_path: Path, upstream: Path) -> Path:
    """An absolute-path wrapper that finds the real server on PATH by its
    file name, the way npx and uvx shims do."""
    script = tmp_path / "netdev-launcher"
    script.write_text(f'#!/bin/sh\nexec {upstream.name} "$@"\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_path_lookup_launcher_fails_fast_without_path(netguard_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> None:
    client = RawClient([str(netguard_binary), *serve_args(_launcher(tmp_path, upstream_binary), fake_device)], env={"PATH": "/usr/bin:/bin"})
    err = _assert_fails_fast(client)
    assert "upstream netdev-ssh-mcp:" in err and "not found" in err


def test_path_lookup_launcher_works_with_upstream_env_path(netguard_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> None:
    """The documented fix for npx/uvx-style upstreams: hand the upstream a
    PATH with `--upstream-env PATH=…`, which overrides the inherited one."""
    path = f"{upstream_binary.parent}{os.pathsep}/usr/bin{os.pathsep}/bin"
    argv = [str(netguard_binary), *serve_args(_launcher(tmp_path, upstream_binary), fake_device, "--upstream-env", f"PATH={path}")]
    client = RawClient(argv, env={"PATH": "/usr/bin:/bin"})
    try:
        assert _list_tools(client) == EXPECTED
    finally:
        client.close()
