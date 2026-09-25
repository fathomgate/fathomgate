# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2 fixtures: spawn `fathomgate serve` in front of a real upstream, with
the fake SSH device (tests/fixtures/device/fake_ssh.py) standing in for the
router (and the fake eAPI device, tests/fixtures/device/fake_eapi.py, for
eos-mcp). Three upstreams, each pinned, each skipped on its own when not
installed (CI requires all three, one job each):

- krisiasty/netdev-ssh-mcp, pinned to NETDEV_SSH_MCP_VERSION (go-sdk, 2026
  era; FATHOMGATE_UPSTREAM, below);
- upa/mcp-netmiko-server, pinned to UPA_COMMIT (FastMCP, 2025 era;
  FATHOMGATE_UPA_*, see upa_install and
  integration/upstreams/upa-mcp-netmiko-server/install.sh);
- shigechika/eos-mcp, pinned to EOS_MCP_VERSION and EOS_MCP_COMMIT (FastMCP,
  pyeapi over HTTPS; FATHOMGATE_EOS_MCP, see eos_mcp_install and
  integration/upstreams/eos-mcp/install.sh).

netdev-ssh-mcp setup (the CI job `client-smoke` does the same):

    make build
    GOBIN=$PWD/.upstream go install github.com/krisiasty/netdev-ssh-mcp@v1.7.1
    cd tests && FATHOMGATE_UPSTREAM=$PWD/../.upstream/netdev-ssh-mcp \\
        uv run --extra integration pytest integration -m tier2 -v

Without FATHOMGATE_UPSTREAM the tests skip (CI sets FATHOMGATE_TIER2_REQUIRED=1,
which turns that skip into a failure); with it set to the wrong version they
fail, because a row is validated only against the named version. The
release binary (netdev-ssh-mcp_1.7.1_<os>_<arch>, checked against the
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
NETDEV_SSH_MCP_VERSION = "v1.7.1"
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


# shigechika/eos-mcp (M1-22, matrix row 4). PyPI eos-mcp 1.3.0, the upload of
# tag v1.3.0 at EOS_MCP_COMMIT, which profiles/eos-mcp.yaml was read at. The
# wheel is hash-pinned in integration/upstreams/eos-mcp/requirements.txt; the
# sha256 of each installed module below is the same file at EOS_MCP_COMMIT,
# so the code that runs is the code the profile cites. Bump these, the
# requirements and test-matrix.md together.
EOS_MCP_VERSION = "1.3.0"
EOS_MCP_COMMIT = "bffb89377b3fa6b544b45b0cab44d5191cf8981a"
EOS_MCP_SHA256 = {
    "__init__.py": "cf066b9732163fdedb7028d6e8954f056c473349053ac6b847db289a7748dfa6",
    "__main__.py": "db4f25c14ad46542974f4fe2fff513a4b96dba7cbde79c80a9c1ed1d738fc2f8",
    "config.py": "c7dc8e72887001fe75d6fb7a428107688be94fe877b66e669c9aa7da320ef2bd",
    "eapi.py": "b52a1787d794260ccc3279cdf0a6ce9429ece76078fd86d95a031296d83ee805",
    "server.py": "7ca4fdfdbff7841688ed4829b56abca1545e691142ab539b99b0ca99f2e12cf2",
}
# The versions the upstream's own uv.lock resolves at EOS_MCP_COMMIT.
EOS_MCP_DEPS = {"mcp": "1.28.1", "pyeapi": "1.0.4"}
# The profile's `server` key, and so the tool prefix.
EOS_SERVER = "eos-mcp"
FAKE_EAPI = REPO / "tests" / "fixtures" / "device" / "fake_eapi.py"
EAPI_USERNAME = "admin"
EAPI_PASSWORD = "FAKE-eapi-pass"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "tier2: real MCP server, fake device")
    config.addinivalue_line("markers", "netdev_ssh_mcp: validated against krisiasty/netdev-ssh-mcp")
    config.addinivalue_line("markers", "upa_mcp_netmiko_server: validated against upa/mcp-netmiko-server")
    config.addinivalue_line("markers", "eos_mcp: validated against shigechika/eos-mcp")


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

    `go install …@v1.7.1` builds leave the upstream's own `-version` at "dev"
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


def owner_only_file(path: Path, content: str) -> Path:
    """Write a configuration file only its owner can change, as `serve
    --policy` requires of the policy and inventory (mode 0600 on Unix; on
    Windows a DACL for the user alone)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    if sys.platform == "win32":
        user = os.environ["USERNAME"]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"], check=True, capture_output=True)
    return path


def tier2_absent(message: str) -> None:
    if os.environ.get("FATHOMGATE_TIER2_REQUIRED") == "1":
        pytest.fail(f"FATHOMGATE_TIER2_REQUIRED=1 but {message}")
    pytest.skip(message)


@pytest.fixture(scope="session")
def eos_mcp_install() -> Path:
    """The `eos-mcp` entry point install.sh made, checked against the pins:
    the distribution version, mcp and pyeapi as the upstream locks them, and
    every eos_mcp module byte for byte as at EOS_MCP_COMMIT."""
    env = os.environ.get("FATHOMGATE_EOS_MCP", "")
    if not env:
        tier2_absent("FATHOMGATE_EOS_MCP is not set (integration/upstreams/eos-mcp/install.sh DEST prints it)")
    exe = Path(env)
    if not exe.is_file():
        pytest.fail(f"FATHOMGATE_EOS_MCP={env!r} does not exist")
    python = exe.parent / ("python.exe" if sys.platform == "win32" else "python")
    probe = (
        "import hashlib, importlib.metadata as m, json, pathlib, eos_mcp\n"
        "d = pathlib.Path(eos_mcp.__file__).parent\n"
        "print(json.dumps({'versions': {n: m.version(n) for n in ('eos-mcp', 'mcp', 'pyeapi')},"
        " 'sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.glob('*.py'))}}))\n"
    )
    out = subprocess.run([str(python), "-c", probe], capture_output=True, text=True, check=False)
    if out.returncode != 0:
        pytest.fail(f"cannot inspect the eos-mcp install next to {exe}: {out.stderr[-500:]}")
    got = json.loads(out.stdout)
    want_versions = {"eos-mcp": EOS_MCP_VERSION, **EOS_MCP_DEPS}
    if got["versions"] != want_versions:
        pytest.fail(f"{python} has {got['versions']}; row 4 is pinned to {want_versions}")
    if got["sha256"] != EOS_MCP_SHA256:
        pytest.fail(f"the installed eos_mcp modules are not those of {EOS_MCP_COMMIT}: {got['sha256']}")
    return exe.resolve()


@dataclass
class FakeEapi:
    """The fake eAPI device's logs (tests/fixtures/device/fake_eapi.py)."""

    port: int
    state: Path
    # The loopback addresses it listens on: 127.0.0.1, and ::1 where the
    # host has an IPv6 loopback, so `localhost` reaches it either way.
    addresses: tuple[str, ...]

    def commands(self) -> list[str]:
        text = (self.state / "commands.log").read_text(encoding="utf-8")
        return [line.split("\t", 1)[1] for line in text.splitlines() if "\t" in line]

    def requests(self) -> list[dict]:
        text = (self.state / "requests.log").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def connections(self) -> list[str]:
        """Every line of connections.log: one peer address per TCP accept,
        then `tls <sni>` or `tls-failed ...`, and `auth-failed <user>`."""
        return (self.state / "connections.log").read_text(encoding="utf-8").splitlines()

    def accepts(self) -> int:
        """TCP connections accepted, before TLS or authentication."""
        return sum(1 for line in self.connections() if not line.startswith(("tls", "auth-failed")))


@pytest.fixture
def fake_eapi(tmp_path: Path):
    """The fake eAPI device on 127.0.0.1:443 (and [::1]:443 where the host
    has an IPv6 loopback), one per test. eos-mcp gives pyeapi no port, so
    443 it is (see fake_eapi.py). A host that may not bind it skips here, or
    fails with FATHOMGATE_TIER2_REQUIRED=1."""
    state = tmp_path / "eapi"
    env = dict(os.environ, FAKE_EAPI_PASSWORD=EAPI_PASSWORD)
    proc = subprocess.Popen(
        [sys.executable, str(FAKE_EAPI), "--state-dir", str(state), "--username", EAPI_USERNAME, "--also-ipv6-loopback"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        line = _readline(proc.stdout, timeout=20)
        if line.startswith("BIND-FAILED"):
            proc.wait(timeout=5)
            tier2_absent(
                f"the fake eAPI device cannot listen on 127.0.0.1:443 ({line}); on Linux run "
                "`sudo sysctl -w net.ipv4.ip_unprivileged_port_start=443`, as CI does"
            )
        if not line.startswith("READY "):
            proc.kill()
            pytest.fail(f"fake eAPI device did not start: {line!r} {proc.stderr.read()!r}")
        _, port, addresses = line.split()
        yield FakeEapi(port=int(port), state=state, addresses=tuple(addresses.split(",")))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def eos_mcp_config(tmp_path: Path, *, verify: str = "false") -> Path:
    """eos-mcp's config.ini: the FAKE eAPI credentials in [DEFAULT] (where
    the upstream's example puts them) and one device, the fake at 127.0.0.1,
    tagged lab. No real credential is ever written here."""
    path = tmp_path / "eos-mcp-config.ini"
    path.write_text(
        "[DEFAULT]\n"
        f"username = {EAPI_USERNAME}\n"
        f"password = {EAPI_PASSWORD}\n"
        "transport = https\n"
        f"verify = {verify}\n"
        "\n[127.0.0.1]\n"
        "tags = lab\n",
        encoding="utf-8",
    )
    return path


@dataclass
class FakeDevice:
    port: int
    known_hosts: Path
    log: Path

    def commands(self) -> list[str]:
        return [line.split("\t", 1)[1] for line in self.log.read_text(encoding="utf-8").splitlines() if "\t" in line]

    def sessions(self) -> int:
        """SSH connections the device has accepted, authenticated or not."""
        return len((self.log.parent / "sessions.log").read_text(encoding="utf-8").splitlines())


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
    # --no-policy: these jobs check the transport, which the pass-through
    # shows unchanged; the policy rows run through --policy (M1-28).
    return ["serve", "--server", SERVER, "--upstream", str(upstream), "--no-policy", *upstream_env_args(device), *extra]


@pytest.fixture
def proxy_server_params(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice) -> dict:
    """StdioServerParameters kwargs for `fathomgate serve` wrapping the upstream.

    A dict so this module imports without the `mcp` package installed. It
    runs serve with --no-policy, the pass-through (ADR 0027); --audit stays
    refused until M4. `env` is the client's `env` block; the python-sdk
    client merges it into HOME, PATH and friends.
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


# --- gated runs (M1-28): policy files, decision lines, a logged session ------

# The example policies' own reasons, quoted exactly (policies/examples/).
NO_EXEC_REASON = "EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"
NO_WRITES_REASON = "this proxy is read-only; configuration changes are denied"
# internal/gate/text.go: the fixed reasons.
UNKNOWN_TARGET_REASON = "target not in inventory"
HELD_REASON = "needs approval, and approvals aren't available yet, so this call was not run."

_DECISION_MSG = re.compile(r"\bmsg=decision\b")


def decision_lines(stderr: Path) -> list[dict[str, str]]:
    """fathomgate's `decision` lines (slog text) from a stderr file, each as a
    key=value map. Values stay strings: `forwarded=false`, `targets=[a b]`."""
    import shlex

    out = []
    for line in stderr.read_text(encoding="utf-8", errors="replace").splitlines():
        if _DECISION_MSG.search(line):
            fields = {}
            for tok in shlex.split(line, posix=True):
                k, sep, v = tok.partition("=")
                if sep:
                    fields[k] = v
            out.append(fields)
    return out


def policy_args(tmp_path: Path, policy: str, inventory: str) -> list[str]:
    """`--policy` and `--inventory` for serve, each written owner-only (ADR
    0027). policy is an example file name under policies/examples/ or, when
    it contains a newline, the policy text itself."""
    body = policy if "\n" in policy else (REPO / "policies/examples" / policy).read_text(encoding="utf-8")
    d = tmp_path / "gate"
    d.mkdir(exist_ok=True)
    n = len(list(d.glob("policy-*.yaml")))
    p = owner_only_file(d / f"policy-{n}.yaml", body)
    i = owner_only_file(d / f"inventory-{n}.yaml", inventory)
    return ["--policy", str(p), "--inventory", str(i)]


def result_text(result) -> str:
    """The text of a python-sdk CallToolResult's content blocks, joined."""
    return "\n".join(getattr(c, "text", "") or "" for c in result.content)


def gate_error(verb: str, server: str, tool: str, rule: str, cls: str, reason: str) -> str:
    """ADR 0026's one tool-error line, exactly."""
    return f"fathomgate {verb} {server}.{tool}: rule {rule} (class {cls}): {reason}"


class LoggedSession:
    """`async with LoggedSession(argv, stderr, env) as session:` an initialised
    python-sdk stdio session to `fathomgate serve`, with fathomgate's stderr
    (the upstream's relayed into it) written to `stderr`."""

    def __init__(self, argv: list[str], stderr: Path, env: dict[str, str] | None = None) -> None:
        self.argv, self.stderr, self.env = argv, stderr, env

    async def __aenter__(self):
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stack = AsyncExitStack()
        errlog = self._stack.enter_context(open(self.stderr, "w", encoding="utf-8"))
        params = StdioServerParameters(command=self.argv[0], args=self.argv[1:], env=self.env)
        read, write = await self._stack.enter_async_context(stdio_client(params, errlog=errlog))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    async def __aexit__(self, *exc):
        await self._stack.aclose()
