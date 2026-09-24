# SPDX-License-Identifier: Apache-2.0
"""Tier 2 fixtures: spawn `fathomgate serve` in front of a real upstream, with
the fake SSH device (tests/fixtures/device/fake_ssh.py) standing in for the
router. Two upstreams, each pinned, each skipped on its own when not
installed (CI requires both):

- krisiasty/netdev-ssh-mcp, pinned to NETDEV_SSH_MCP_VERSION (go-sdk, 2026
  era; FATHOMGATE_UPSTREAM, below);
- upa/mcp-netmiko-server, pinned to UPA_COMMIT (FastMCP, 2025 era;
  FATHOMGATE_UPA_*, see upa_install and
  integration/upstreams/upa-mcp-netmiko-server/install.sh).

netdev-ssh-mcp setup (the CI job `client-smoke` does the same):

    make build
    GOBIN=$PWD/.upstream go install github.com/krisiasty/netdev-ssh-mcp@v1.6.6
    cd tests && FATHOMGATE_UPSTREAM=$PWD/../.upstream/netdev-ssh-mcp \\
        uv run --extra integration pytest integration -m tier2 -v

Without FATHOMGATE_UPSTREAM the tests skip (CI sets FATHOMGATE_TIER2_REQUIRED=1,
which turns that skip into a failure); with it set to the wrong version they
fail, because a row is validated only against the named version. The
release binary (netdev-ssh-mcp_1.6.6_<os>_<arch>, checked against the
release's checksums.txt) and a `go install` build both qualify.
Everything the upstream returns is data: the tests compare it, never act
on it.
"""

from __future__ import annotations

import hashlib
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


# upa/mcp-netmiko-server (T0.34, matrix row 2). It has no releases, so the
# pin is a commit, plus main.py's sha256 (the server is that one file). Bump
# these, install.sh and test-matrix.md together.
UPA_COMMIT = "96e8ff321cc839eeb525474736439ddc2ebc795c"
UPA_MAIN_SHA256 = "07e55298409e91dea62e2f245fad37be75e71a0dd8df9027f97ba0c7cca7babb"
# The two dependency sets the upstream runs with (install.sh): "current" is
# integration/upstreams/upa-mcp-netmiko-server/requirements.txt, "locked" is
# the upstream's own uv.lock.
UPA_CURRENT_MCP = "1.30.0"
UPA_LOCKED_MCP = "1.6.0"
# The tool prefix. Short on purpose: the upstream's longest tool name
# (set_config_commands_and_commit_or_save) is 38 characters, and Claude Code's
# `mcp__<key>__<server>_<tool>` must stay within 64.
UPA_SERVER = "upa"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tier2: real MCP server, fake device")
    config.addinivalue_line("markers", "netdev_ssh_mcp: validated against krisiasty/netdev-ssh-mcp")
    config.addinivalue_line("markers", "upa_mcp_netmiko_server: validated against upa/mcp-netmiko-server")


@pytest.fixture(scope="session")
def fathomgate_binary() -> Path:
    """Absolute path to a built fathomgate binary (`make build`), or skip."""
    env = os.environ.get("FATHOMGATE_BIN")
    candidates = [Path(env)] if env else []
    candidates += [REPO / "bin" / "fathomgate", Path(shutil.which("fathomgate") or "/nonexistent")]
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c.resolve()
    if os.environ.get("FATHOMGATE_TIER2_REQUIRED") == "1":
        pytest.fail("FATHOMGATE_TIER2_REQUIRED=1 but no fathomgate binary; run `make build`")
    pytest.skip("fathomgate binary not built; run `make build` or set FATHOMGATE_BIN")


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
    env = os.environ.get("FATHOMGATE_UPSTREAM")
    if not env and os.environ.get("FATHOMGATE_TIER2_REQUIRED") == "1":
        pytest.fail("FATHOMGATE_TIER2_REQUIRED=1 but FATHOMGATE_UPSTREAM is not set")
    if not env:
        pytest.skip(f"FATHOMGATE_UPSTREAM not set (go install github.com/krisiasty/netdev-ssh-mcp@{NETDEV_SSH_MCP_VERSION})")
    found = shutil.which(env) if os.sep not in env else env
    if not found or not Path(found).is_file():
        pytest.fail(f"FATHOMGATE_UPSTREAM={env!r} is not an executable")
    path = Path(found).resolve()
    version = _module_version(path)
    if version != NETDEV_SSH_MCP_VERSION:
        pytest.fail(f"{path} is netdev-ssh-mcp {version!r}; these rows are pinned to {NETDEV_SSH_MCP_VERSION}")
    return path


@dataclass
class UpaInstall:
    main: Path  # main.py at UPA_COMMIT
    python: Path  # the "current" leg: mcp UPA_CURRENT_MCP
    locked_python: Path  # the "locked" leg: the upstream's uv.lock, mcp UPA_LOCKED_MCP


def _mcp_version(python: Path) -> str:
    out = subprocess.run(
        [str(python), "-c", "from importlib.metadata import version; print(version('mcp'))"],
        capture_output=True,
        text=True,
        check=False,
    )
    return out.stdout.strip() or out.stderr.strip()


@pytest.fixture(scope="session")
def upa_install() -> UpaInstall:
    """upa/mcp-netmiko-server as install.sh lays it out, checked against the pins."""
    names = ("FATHOMGATE_UPA_DIR", "FATHOMGATE_UPA_PYTHON", "FATHOMGATE_UPA_LOCKED_PYTHON")
    values = {n: os.environ.get(n, "") for n in names}
    missing = [n for n, v in values.items() if not v]
    hint = "integration/upstreams/upa-mcp-netmiko-server/install.sh DEST prints them"
    if missing and os.environ.get("FATHOMGATE_TIER2_REQUIRED") == "1":
        pytest.fail(f"FATHOMGATE_TIER2_REQUIRED=1 but {', '.join(missing)} not set ({hint})")
    if missing:
        pytest.skip(f"{', '.join(missing)} not set ({hint})")
    main = Path(values["FATHOMGATE_UPA_DIR"]) / "main.py"
    if not main.is_file():
        pytest.fail(f"{main} does not exist")
    digest = hashlib.sha256(main.read_bytes()).hexdigest()
    if digest != UPA_MAIN_SHA256:
        pytest.fail(f"{main} has sha256 {digest}; row 2 is pinned to upa/mcp-netmiko-server {UPA_COMMIT} ({UPA_MAIN_SHA256})")
    for name, want in (("FATHOMGATE_UPA_PYTHON", UPA_CURRENT_MCP), ("FATHOMGATE_UPA_LOCKED_PYTHON", UPA_LOCKED_MCP)):
        got = _mcp_version(Path(values[name]))
        if got != want:
            pytest.fail(f"{name}={values[name]} has mcp {got!r}; want {want}")
    return UpaInstall(
        main=main.resolve(),
        python=Path(values["FATHOMGATE_UPA_PYTHON"]),
        locked_python=Path(values["FATHOMGATE_UPA_LOCKED_PYTHON"]),
    )


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
    """fathomgate passes the upstream only an allow-list of its own environment,
    so device settings are handed over explicitly, the way docs/install.md
    shows: non-secrets with `--upstream-env NAME=value`, the password with
    `--upstream-env-pass DEVICE_PASSWORD` (ADR 0017), so it is never on the
    command line. The password itself comes from fathomgate's environment:
    see client_env."""
    args = ["--upstream-env", f"DEVICE_USERNAME={DEVICE_USERNAME}", "--upstream-env-pass", "DEVICE_PASSWORD"]
    if device is not None:
        args += ["--upstream-env", f"SSH_KNOWN_HOSTS={device.known_hosts}"]
    return args


def client_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """fathomgate's environment as a client with an `env` block
    ({"DEVICE_PASSWORD": ...}) sets it: env plus the fake device password."""
    return {**(env or {}), "DEVICE_PASSWORD": DEVICE_PASSWORD}


def serve_args(upstream: Path | str, device: FakeDevice | None, *extra: str) -> list[str]:
    return ["serve", "--server", SERVER, "--upstream", str(upstream), *upstream_env_args(device), *extra]


@pytest.fixture
def proxy_server_params(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> dict:
    """StdioServerParameters kwargs for `fathomgate serve` wrapping the upstream.

    A dict so this module imports without the `mcp` package installed. M0
    serve is pass-through: --policy, --inventory, --profiles and --audit are
    refused until M1 wires the pipeline (ADR 0012). `env` is the client's
    `env` block; the python-sdk client merges it into HOME, PATH and friends.
    """
    return {"command": str(fathomgate_binary), "args": serve_args(upstream_binary, fake_device), "env": client_env()}


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
                raise EOFError(f"fathomgate closed stdout before answering {method}")
            msg = json.loads(line)
            if msg.get("id") == id_:
                return msg

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def initialize(self) -> dict:
        resp = self.request(1, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fathomgate-tier2", "version": "0"}})
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
