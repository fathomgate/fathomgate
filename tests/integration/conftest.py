"""Tier 2 fixtures: spawn `netguard serve` in front of the real upstream
krisiasty/netdev-ssh-mcp, pinned to NETDEV_SSH_MCP_VERSION, with the fake
SSH device (tests/fixtures/device/fake_ssh.py) standing in for the router.

Setup (the CI job `client-smoke` does the same):

    make build
    GOBIN=$PWD/.upstream go install github.com/krisiasty/netdev-ssh-mcp@v1.6.6
    cd tests && NETGUARD_UPSTREAM=$PWD/../.upstream/netdev-ssh-mcp \\
        uv run --extra integration pytest integration -m tier2 -v

Without NETGUARD_UPSTREAM the tests skip (CI sets NETGUARD_TIER2_REQUIRED=1,
which turns that skip into a failure); with it set to the wrong version they
fail, because a row is validated only against the named version. The
release binary (netdev-ssh-mcp_1.6.6_<os>_<arch>, checked against the
release's checksums.txt) and a `go install` build both qualify.
Everything the upstream returns is data: the tests compare it, never act
on it.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FAKE_DEVICE = REPO / "tests" / "fixtures" / "device" / "fake_ssh.py"

# The one netdev-ssh-mcp release matrix rows 1 and 22 are run against.
# Bump it in its own PR, with the CI job and test-matrix.md Evidence.
NETDEV_SSH_MCP_VERSION = "v1.6.6"
SERVER = "netdev-ssh-mcp"

DEVICE_USERNAME = "admin"
DEVICE_PASSWORD = "FAKE-device-pass"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tier2: real MCP server, fake device")
    config.addinivalue_line("markers", "netdev_ssh_mcp: validated against krisiasty/netdev-ssh-mcp")


@pytest.fixture(scope="session")
def netguard_binary() -> Path:
    """Absolute path to a built netguard binary (`make build`), or skip."""
    env = os.environ.get("NETGUARD_BIN")
    candidates = [Path(env)] if env else []
    candidates += [REPO / "bin" / "netguard", Path(shutil.which("netguard") or "/nonexistent")]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    if os.environ.get("NETGUARD_TIER2_REQUIRED") == "1":
        pytest.fail("NETGUARD_TIER2_REQUIRED=1 but no netguard binary; run `make build`")
    pytest.skip("netguard binary not built; run `make build` or set NETGUARD_BIN")


def _module_version(binary: Path) -> str | None:
    """The main-module version recorded in a Go binary, via `go version -m`.

    `go install …@v1.6.6` builds leave the upstream's own `-version` at "dev"
    (no ldflags), so the build info is the reliable pin check.
    """
    go = shutil.which("go")
    if go:
        out = subprocess.run([go, "version", "-m", str(binary)], capture_output=True, text=True, check=False).stdout
        m = re.search(r"^\s*mod\s+github\.com/krisiasty/netdev-ssh-mcp\s+(v\d+\.\d+\.\d+\S*)", out, re.M)
        if m:
            return m.group(1)
    out = subprocess.run([str(binary), "-version"], capture_output=True, text=True, check=False).stdout
    m = re.search(r"^version:\s*(\S+)", out, re.M)
    if m and m.group(1) != "dev":
        v = m.group(1)
        return v if v.startswith("v") else "v" + v
    return None


@pytest.fixture(scope="session")
def upstream_binary() -> Path:
    """Absolute path to the netdev-ssh-mcp binary, checked against the pin."""
    env = os.environ.get("NETGUARD_UPSTREAM")
    if not env and os.environ.get("NETGUARD_TIER2_REQUIRED") == "1":
        pytest.fail("NETGUARD_TIER2_REQUIRED=1 but NETGUARD_UPSTREAM is not set")
    if not env:
        pytest.skip(f"NETGUARD_UPSTREAM not set (go install github.com/krisiasty/netdev-ssh-mcp@{NETDEV_SSH_MCP_VERSION})")
    found = shutil.which(env) if os.sep not in env else env
    if not found or not Path(found).is_file():
        pytest.fail(f"NETGUARD_UPSTREAM={env!r} is not an executable")
    path = Path(found).resolve()
    version = _module_version(path)
    if version != NETDEV_SSH_MCP_VERSION:
        pytest.fail(f"{path} is netdev-ssh-mcp {version!r}; these rows are pinned to {NETDEV_SSH_MCP_VERSION}")
    return path


@dataclass
class FakeDevice:
    port: int
    known_hosts: Path
    log: Path

    def commands(self) -> list[str]:
        return [line.split("\t", 1)[1] for line in self.log.read_text(encoding="utf-8").splitlines() if "\t" in line]


@pytest.fixture
def fake_device(tmp_path: Path):
    """The fake EOS device on 127.0.0.1, one per test."""
    state = tmp_path / "device"
    env = dict(os.environ, FAKE_DEVICE_PASSWORD=DEVICE_PASSWORD)
    proc = subprocess.Popen(
        [sys.executable, str(FAKE_DEVICE), "--vendor", "eos", "--state-dir", str(state), "--username", DEVICE_USERNAME],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        line = _readline(proc.stdout, timeout=20)
        if not line.startswith("READY "):
            proc.kill()
            pytest.fail(f"fake device did not start: {line!r} {proc.stderr.read()!r}")
        yield FakeDevice(port=int(line.split()[1]), known_hosts=state / "known_hosts", log=state / "commands.log")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def upstream_env_args(device: FakeDevice | None) -> list[str]:
    """netguard passes the upstream only an allow-list of its own environment,
    so device settings are handed over explicitly, the way docs/install.md
    shows: non-secrets with `--upstream-env NAME=value`, the password with
    `--upstream-env-pass DEVICE_PASSWORD` (ADR 0017), so it is never on the
    command line. The password itself comes from netguard's environment:
    see client_env."""
    args = ["--upstream-env", f"DEVICE_USERNAME={DEVICE_USERNAME}", "--upstream-env-pass", "DEVICE_PASSWORD"]
    if device is not None:
        args += ["--upstream-env", f"SSH_KNOWN_HOSTS={device.known_hosts}"]
    return args


def client_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """netguard's environment as a client with an `env` block
    ({"DEVICE_PASSWORD": ...}) sets it: env plus the fake device password."""
    return {**(env or {}), "DEVICE_PASSWORD": DEVICE_PASSWORD}


def serve_args(upstream: Path | str, device: FakeDevice | None, *extra: str) -> list[str]:
    return ["serve", "--server", SERVER, "--upstream", str(upstream), *upstream_env_args(device), *extra]


@pytest.fixture
def proxy_server_params(netguard_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> dict:
    """StdioServerParameters kwargs for `netguard serve` wrapping the upstream.

    A dict so this module imports without the `mcp` package installed. M0
    serve is pass-through: --policy, --inventory, --profiles and --audit are
    refused until M1 wires the pipeline (ADR 0012). `env` is the client's
    `env` block; the python-sdk client merges it into HOME, PATH and friends.
    """
    return {"command": str(netguard_binary), "args": serve_args(upstream_binary, fake_device), "env": client_env()}


def _readline(stream, timeout: float) -> str:
    box: list[str] = []
    t = threading.Thread(target=lambda: box.append(stream.readline()), daemon=True)
    t.start()
    t.join(timeout)
    if not box:
        raise TimeoutError(f"no line within {timeout}s")
    return box[0].strip()


class RawClient:
    """A newline-delimited JSON-RPC client over a child's stdio, for the
    launcher cases that need an exact environment (`env -i`), which the
    python-sdk stdio client cannot give: it always merges HOME, PATH, USER
    and friends from the test runner."""

    def __init__(self, argv: list[str], env: dict[str, str]) -> None:
        self.started = time.monotonic()
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)

    def request(self, id_: int, method: str, params: dict, timeout: float = 20) -> dict:
        self._send({"jsonrpc": "2.0", "id": id_, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no response to {method} within {timeout}s")
            line = _readline(self.proc.stdout, left)
            if not line:
                raise EOFError(f"netguard closed stdout before answering {method}")
            msg = json.loads(line)
            if msg.get("id") == id_:
                return msg

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def initialize(self) -> dict:
        resp = self.request(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "netguard-tier2", "version": "0"}})
        self.notify("notifications/initialized")
        return resp

    def wait(self, timeout: float) -> tuple[int, str, float]:
        """Exit status, stderr and seconds since start; kills on timeout."""
        try:
            _, err = self.proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
            raise
        return self.proc.returncode, err, time.monotonic() - self.started

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def _send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
