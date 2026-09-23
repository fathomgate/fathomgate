"""Tier 2 fixtures: spawn `netguard serve` in front of a real upstream MCP
server and hand the test an MCP client connected to the proxy.

Nothing here runs until M0 lands; the fixtures exist so the tests can show
their intended shape and so `pytest --collect-only` is green.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tier2: real MCP server in a container, fake device")


@pytest.fixture(scope="session")
def netguard_binary() -> Path:
    """Path to a built netguard binary (`make build`), or skip."""
    env = os.environ.get("NETGUARD_BIN")
    candidates = [Path(env)] if env else []
    candidates += [REPO / "bin" / "netguard", Path(shutil.which("netguard") or "/nonexistent")]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    pytest.skip("netguard binary not built; run `make build` or set NETGUARD_BIN")


@pytest.fixture(scope="session")
def upstream_command() -> list[str]:
    """Command that starts the real upstream server over stdio.

    The reference read-only upstream is krisiasty/netdev-ssh-mcp. Point
    NETGUARD_UPSTREAM at an installed binary; tier 2 in CI will start the
    server image with testcontainers instead.
    """
    env = os.environ.get("NETGUARD_UPSTREAM")
    if not env:
        pytest.skip("NETGUARD_UPSTREAM not set (e.g. 'netdev-ssh-mcp')")
    return env.split()


@pytest.fixture
def proxy_server_params(netguard_binary: Path, upstream_command: list[str], tmp_path: Path):
    """StdioServerParameters for `netguard serve` wrapping the upstream.

    Returned lazily as a dict so this module imports without the `mcp`
    package installed; test_passthrough turns it into the SDK type.
    """
    # M0 serve is pass-through: --policy, --inventory, --profiles and --audit
    # are refused until M1 wires the pipeline (ADR 0012). The prefix is the
    # profile `server` key; upstream arguments follow `--`.
    return {
        "command": str(netguard_binary),
        "args": [
            "serve",
            "--server", "netdev-ssh-mcp",
            "--upstream", upstream_command[0],
            "--",
            *upstream_command[1:],
        ],
    }
