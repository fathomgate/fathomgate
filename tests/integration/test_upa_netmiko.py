# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2: `fathomgate serve` in front of the real 2025-era upstream
upa/mcp-netmiko-server (FastMCP, one file, pinned by commit and sha256 in
conftest), which reaches the fake SSH device through netmiko's interactive
shell (`device_type = "arista_eos"`).

Matrix row 2 (dual-era handshake), the 2025-era half. The 2026-era half is
netdev-ssh-mcp in test_passthrough.py. M0 exit criterion 3.

The upstream runs with two dependency sets (install.sh):

- current: its code with mcp 1.30.0, the newest 1.x, which its pyproject.toml
  (`mcp[cli]>=1.6.0`) allows. fathomgate's go-sdk client sends `server/discover`,
  the upstream answers with an error, and go-sdk falls back to `initialize`:
  2025-11-25, stateful. Every fathomgate assertion below runs on this set.
- locked: its own uv.lock, mcp 1.6.0 (2024-11-05 only). That SDK does not
  answer a request whose method it does not know: its receive loop dies, and
  the process lives on without reading. So fathomgate's `server/discover` gets
  no answer. The upstream's side of that is asserted directly. fathomgate's
  side (ADR 0018, T0.39): after 5 seconds without an answer it kills the
  upstream, starts it again and connects with `initialize` only, which that
  SDK answers with 2024-11-05.

Not covered here: upa's three tools take no Context and never elicit
(main.py at the pinned commit), so the ADR 0014 case (a 2026 agent calling a
tool whose stateful upstream sends elicitation/create) cannot happen against
this upstream. tests/conformance/era_pairs.py covers it against go-sdk
v1.6.1's conformance server.

Everything the upstream returns is data: compared, never acted on.
"""

from __future__ import annotations

import json
import queue
import re
import subprocess
import threading
import time
from pathlib import Path

import pytest

from .conftest import (
    NO_EXEC_REASON,
    NO_WRITES_REASON,
    REPO,
    UNKNOWN_TARGET_REASON,
    UPA_SERVER,
    FakeDevice,
    LoggedSession,
    UpaInstall,
    decision_lines,
    gate_error,
    policy_args,
    result_text,
)

pytestmark = [pytest.mark.tier2, pytest.mark.upa_mcp_netmiko_server]

V2025 = "2025-11-25"
V2026 = "2026-07-28"
DEVICE = "fake-eos"
DEVICE_PASSWORD = "FAKE-device-pass"  # conftest.DEVICE_PASSWORD; upa reads it from its TOML inventory

# The upstream's full tool set at the pinned commit. Equality, not subset.
UPSTREAM_TOOLS = {"get_network_device_list", "send_command_and_get_output", "set_config_commands_and_commit_or_save"}

SHOW_VERSION = (REPO / "tests/fixtures/device/transcripts/eos/show_version.txt").read_text()

# What netmiko 4.5.0's arista_eos driver types into the shell for one
# send_command: session preparation (terminal width, paging off), the
# command, then `exit` on disconnect. The device sees `show version` once.
NETMIKO_SESSION = ["terminal width 511", "terminal length 0", "show version", "exit"]

# fathomgate's startup line for the upstream (slog text handler).
READY = re.compile(r'msg="upstream ready" server=(\S+) tools=(\d+) protocol=(\S+) era=(\S+)')


class FathomgateExited(Exception):
    """fathomgate closed stdout before answering."""


class Fathomgate:
    """`fathomgate serve` over stdio, one JSON-RPC message per line, with its
    stderr collected (the upstream's stderr is relayed there too)."""

    def __init__(self, argv: list[str]) -> None:
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.stderr: list[str] = []
        threading.Thread(target=self._pump_out, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump_out(self) -> None:
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _pump_err(self) -> None:
        for line in self.proc.stderr:
            self.stderr.append(line.rstrip("\n"))

    def send(self, msg: dict) -> None:
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
        self.proc.stdin.flush()

    def request(self, id_: int, method: str, params: dict, timeout: float = 40) -> dict:
        """The response to one request; notifications in between are skipped.
        A server-initiated request fails the test: upa never sends one."""
        self.send({"id": id_, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = self.lines.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise TimeoutError(f"no response to {method} within {timeout:.0f}s") from None
            if line is None:
                try:
                    code = self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    code = None
                tail = "\n".join(l for l in self.stderr if not l.startswith(f"upstream {UPA_SERVER}:"))[-2000:]
                raise FathomgateExited(f"fathomgate exited ({code}) before answering {method}:\n{tail}")
            msg = json.loads(line)
            if "method" in msg and "id" in msg:
                raise AssertionError(f"server-initiated request reached the agent: {msg['method']}")
            if msg.get("id") == id_:
                return msg

    def ready(self, timeout: float = 5) -> tuple[str, int, str, str]:
        """(server, tools, protocol, era) from the `upstream ready` line.
        fathomgate writes it before it serves the agent, but stderr is read on
        its own thread, so allow it a moment to arrive."""
        deadline = time.monotonic() + timeout
        while True:
            for line in list(self.stderr):
                if m := READY.search(line):
                    return m.group(1), int(m.group(2)), m.group(3), m.group(4)
            if time.monotonic() > deadline:
                raise AssertionError("fathomgate logged no `upstream ready` line:\n" + "\n".join(self.stderr[-20:]))
            time.sleep(0.05)

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def _texts(result: dict) -> str:
    return "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")


def _inventory(tmp_path: Path, device: FakeDevice, extra: tuple[str, ...] = ()) -> Path:
    """upa's TOML inventory: the fake EOS box as DEVICE, plus any `extra`
    names, each also pointing at the fake device (so a forwarded call to one
    would really connect). The password is a FAKE fixture; upa has no other
    way to take it."""
    toml = tmp_path / "devices.toml"
    body = "[default]\n" 'username = "admin"\n' f'password = "{DEVICE_PASSWORD}"\n' f"port = {device.port}\n"
    for name in (DEVICE, *extra):
        body += f"\n[{name}]\n" 'hostname = "127.0.0.1"\n' 'device_type = "arista_eos"\n'
    toml.write_text(body, encoding="utf-8")
    return toml


def _serve(fathomgate: Path, python: Path, main: Path, toml: Path) -> list[str]:
    return [str(fathomgate), "serve", "--server", UPA_SERVER, "--upstream", str(python), "--no-policy", "--", str(main), str(toml)]


@pytest.fixture
def upa_argv(fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path) -> list[str]:
    """fathomgate serve in front of upa on mcp 1.30.0 (the current leg)."""
    return _serve(fathomgate_binary, upa_install.python, upa_install.main, _inventory(tmp_path, fake_device))


@pytest.fixture
def ng(upa_argv: list[str]):
    n = Fathomgate(upa_argv)
    yield n
    n.close()


def _initialize_2025(ng: Fathomgate) -> dict:
    resp = ng.request(1, "initialize", {"protocolVersion": V2025, "capabilities": {}, "clientInfo": {"name": "fathomgate-tier2", "version": "0"}})
    ng.send({"method": "notifications/initialized"})
    return resp


META_2026 = {
    "io.modelcontextprotocol/protocolVersion": V2026,
    "io.modelcontextprotocol/clientInfo": {"name": "fathomgate-tier2", "version": "0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _call_show_version(ng: Fathomgate, id_: int, meta: dict | None = None) -> dict:
    params: dict = {"name": f"{UPA_SERVER}.send_command_and_get_output", "arguments": {"name": DEVICE, "command": "show version"}}
    if meta is not None:
        params["_meta"] = meta
    return ng.request(id_, "tools/call", params)


# --- current leg: upa at the pinned commit on mcp 1.30.0 ---------------------


def test_upstream_negotiates_2025_11_25_stateful(ng: Fathomgate) -> None:
    """fathomgate tried the stateless era first, the upstream refused
    `server/discover`, and the initialise fallback settled on 2025-11-25:
    fathomgate logs `upstream ready server=upa tools=3 protocol=2025-11-25
    era=stateful`."""
    resp = _initialize_2025(ng)
    assert resp["result"]["serverInfo"]["name"] == "fathomgate"
    assert ng.ready() == (UPA_SERVER, len(UPSTREAM_TOOLS), V2025, "stateful")
    # The fallback happened: the upstream logged its own refusal of the
    # stateless probe (mcp 1.30.0 answers an unknown method with an error),
    # relayed by fathomgate with the `upstream upa: ` prefix.
    assert any(l.startswith(f"upstream {UPA_SERVER}: ") and "input_value='server/discover'" in l for l in list(ng.stderr))


def test_tools_list_prefixed_for_2025_agent(ng: Fathomgate) -> None:
    """A 2025-11-25 agent sees exactly the upstream's three tools as `upa.<tool>`."""
    init = _initialize_2025(ng)
    assert init["result"]["protocolVersion"] == V2025
    tools = ng.request(2, "tools/list", {})["result"]["tools"]
    names = sorted(t["name"] for t in tools)
    assert names == sorted(f"{UPA_SERVER}.{t}" for t in UPSTREAM_TOOLS)
    # Claude Code's mcp__<config key>__<tool> within 64, with the key "upa".
    assert all(len(f"mcp__{UPA_SERVER}__{n}") <= 64 for n in names)
    send = next(t for t in tools if t["name"] == f"{UPA_SERVER}.send_command_and_get_output")
    assert set(send["inputSchema"]["required"]) == {"name", "command"}


def test_show_version_reaches_device_once_for_2025_agent(ng: Fathomgate, fake_device: FakeDevice) -> None:
    """A read-only call from a 2025-11-25 agent: `show version` runs once on
    the device, and the transcript comes back unchanged (M0 forwards: no
    policy, no redaction)."""
    _initialize_2025(ng)
    resp = _call_show_version(ng, 2)
    result = resp["result"]
    assert result.get("isError") is not True, resp
    assert _texts(result).strip() == SHOW_VERSION.strip()
    assert fake_device.commands() == NETMIKO_SESSION
    assert ng.ready()[2:] == (V2025, "stateful")


def test_2026_agent_through_fathomgate_to_2025_upstream(ng: Fathomgate, fake_device: FakeDevice) -> None:
    """A 2026-07-28 agent (no initialize; every request carries `_meta`) lists
    and calls the 2025-11-25 upstream through fathomgate. The upstream side
    stays stateful; no `_meta` crosses it."""
    disc = ng.request(1, "server/discover", {"_meta": META_2026})
    assert V2026 in disc["result"]["supportedVersions"], disc
    tools = ng.request(2, "tools/list", {"_meta": META_2026})["result"]["tools"]
    assert sorted(t["name"] for t in tools) == sorted(f"{UPA_SERVER}.{t}" for t in UPSTREAM_TOOLS)
    resp = _call_show_version(ng, 3, META_2026)
    result = resp["result"]
    assert result.get("isError") is not True, resp
    assert _texts(result).strip() == SHOW_VERSION.strip()
    assert fake_device.commands() == NETMIKO_SESSION
    assert ng.ready()[2:] == (V2025, "stateful")


@pytest.mark.asyncio
async def test_python_sdk_client_through_fathomgate(upa_argv: list[str], fake_device: FakeDevice) -> None:
    """The same read with a real client library, as test_passthrough.py does
    for netdev-ssh-mcp. python-sdk mcp 2.2.0's stdio client initialises at
    2025-11-25 with fathomgate, so this is a second 2025 agent; the 2026 agent
    is the raw client above."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=upa_argv[0], args=upa_argv[1:])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            assert init.server_info.name == "fathomgate"
            assert init.protocol_version == V2025
            names = sorted(t.name for t in (await session.list_tools()).tools)
            result = await session.call_tool(f"{UPA_SERVER}.send_command_and_get_output", {"name": DEVICE, "command": "show version"})

    assert names == sorted(f"{UPA_SERVER}.{t}" for t in UPSTREAM_TOOLS)
    assert not result.is_error
    assert "".join(getattr(c, "text", "") or "" for c in result.content).strip() == SHOW_VERSION.strip()
    assert fake_device.commands() == NETMIKO_SESSION


# --- locked leg: upa at the pinned commit on its own uv.lock (mcp 1.6.0) -----


def _raw_upstream(install: UpaInstall, toml: Path) -> subprocess.Popen:
    return subprocess.Popen(
        [str(install.locked_python), str(install.main), str(toml)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _exchange(proc: subprocess.Popen, messages: list[dict], want: int, wait: float) -> tuple[list[dict], str]:
    """Send messages; collect replies until `want` arrive or `wait` seconds
    pass; then kill the upstream (the locked one never exits on its own once
    its receive loop has died) and return the replies and its stderr."""
    replies: queue.Queue[str] = queue.Queue()

    def pump() -> None:
        for line in proc.stdout:
            if line.strip():
                replies.put(line)

    threading.Thread(target=pump, daemon=True).start()
    for m in messages:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", **m}) + "\n")
    proc.stdin.flush()
    got: list[dict] = []
    deadline = time.monotonic() + wait
    while len(got) < want or want == 0:
        try:
            got.append(json.loads(replies.get(timeout=max(0.0, deadline - time.monotonic()))))
        except queue.Empty:
            break
    proc.kill()
    _, err = proc.communicate()
    return got, err


INIT_2025 = {"id": 1, "method": "initialize", "params": {"protocolVersion": V2025, "capabilities": {}, "clientInfo": {"name": "fathomgate-tier2", "version": "0"}}}
# What go-sdk v1.8 sends first (mcp/client.go, Client.Connect).
DISCOVER = {"id": 0, "method": "server/discover", "params": {"_meta": META_2026}}


def test_locked_upstream_speaks_2024_11_05(upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path) -> None:
    """Direct, no fathomgate: the upstream as its authors lock it answers a
    2025-11-25 initialize with 2024-11-05, the only version mcp 1.6.0 knows."""
    replies, _ = _exchange(_raw_upstream(upa_install, _inventory(tmp_path, fake_device)), [INIT_2025], want=1, wait=20)
    assert [r.get("id") for r in replies] == [1]
    assert replies[0]["result"]["protocolVersion"] == "2024-11-05"


def test_locked_upstream_stops_answering_after_server_discover(upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path) -> None:
    """Direct, no fathomgate: after `server/discover` the locked upstream answers
    nothing, not even a following initialize. The SDK's receive loop raised
    on the unknown method (a pydantic ValidationError) instead of replying
    -32601. This is the upstream's defect; fathomgate's handling of it (ADR
    0018) is the test below."""
    # 5 s: the same upstream answers a lone initialize in about 1 s (above).
    replies, err = _exchange(_raw_upstream(upa_install, _inventory(tmp_path, fake_device)), [DISCOVER, INIT_2025], want=0, wait=5)
    assert replies == []
    assert "ValidationError" in err and "input_value='server/discover'" in err


def test_locked_upstream_initialises_behind_fathomgate(fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path) -> None:
    """Row 2 for the upstream as shipped: the server/discover probe goes
    unanswered, fathomgate restarts the upstream once and connects with
    initialize only (ADR 0018), reaches it at 2024-11-05, stateful, and
    serves its tools. The restart is logged once, at warn."""
    ng = Fathomgate(_serve(fathomgate_binary, upa_install.locked_python, upa_install.main, _inventory(tmp_path, fake_device)))
    try:
        _initialize_2025(ng)
        tools = ng.request(2, "tools/list", {})["result"]["tools"]
        assert sorted(t["name"] for t in tools) == sorted(f"{UPA_SERVER}.{t}" for t in UPSTREAM_TOOLS)
        assert ng.ready() == (UPA_SERVER, len(UPSTREAM_TOOLS), "2024-11-05", "stateful")
        restarts = [line for line in ng.stderr if "did not answer server/discover within 5s" in line]
        assert len(restarts) == 1 and "level=WARN" in restarts[0], ng.stderr[-20:]
    finally:
        ng.close()


# --- through the gate (M1-28): row 4, the upa half ----------------------------

GATE_INVENTORY = f"devices:\n  - name: {DEVICE}\n    role: lab\n    tags: [lab]\n"
SHOW_BGP = (REPO / "tests/fixtures/device/transcripts/eos/show_ip_bgp_summary.txt").read_text(encoding="utf-8")


def _gated_argv(
    fathomgate: Path, upa_install: UpaInstall, device: FakeDevice, tmp_path: Path, policy: str, upa_extra: tuple[str, ...] = ()
) -> list[str]:
    """fathomgate serve --policy <policy> --inventory <fake-eos only> in
    front of upa on mcp 1.30.0, with the embedded profile (profiles/upa.yaml).
    upa_extra adds names to upa's own TOML (not to fathomgate's inventory)."""
    argv = _serve(fathomgate, upa_install.python, upa_install.main, _inventory(tmp_path, device, upa_extra))
    i = argv.index("--no-policy")
    return argv[:i] + policy_args(tmp_path, policy, GATE_INVENTORY) + argv[i + 1 :]


def _drow(d: dict[str, str]) -> tuple[str, ...]:
    return (d["tool"], d["decision"], d["rule_id"], d["class"], d["class_source"], d["forwarded"])


@pytest.mark.asyncio
async def test_row4_control_reload_reaches_device_without_policy(upa_argv: list[str], fake_device: FakeDevice, tmp_path: Path) -> None:
    """The control for row 4 on upa: with `--no-policy` and no `--secured`,
    the same `reload` call is forwarded and the fake device receives it.
    So when the gated test below sees no `reload`, the gate stopped a
    command that would have arrived."""
    stderr = tmp_path / "fathomgate.stderr"
    async with LoggedSession(upa_argv, stderr) as session:
        await session.call_tool(f"{UPA_SERVER}.send_command_and_get_output", {"name": DEVICE, "command": "reload"})
    assert "reload" in fake_device.commands()
    assert decision_lines(stderr) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["read-only.yaml", "prod-approval.yaml"])
async def test_row4_reload_denied_show_downgraded(
    fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path, policy: str
) -> None:
    """Row 4, upa half, and M1 exit criterion 3 on this upstream.

    send_command_and_get_output is EXEC_ARBITRARY in the profile. `show
    version` and `show ip bgp summary` pass the read allow-list, so they are
    downgraded to READ_OPERATIONAL (class_source downgrade) and allow by
    `reads-anywhere`; each runs once on the device through netmiko. `reload`
    stays EXEC_ARBITRARY and is deny by `no-exec`, with the exact tool
    error, and the device logs no new SSH session and no command. upa runs
    without --secured here, so the gate is the only thing between the agent
    and `reload`."""
    stderr = tmp_path / "fathomgate.stderr"
    tool = "send_command_and_get_output"
    async with LoggedSession(_gated_argv(fathomgate_binary, upa_install, fake_device, tmp_path, policy), stderr) as session:
        show = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": "show version"})
        assert not show.is_error, result_text(show)
        assert result_text(show).strip() == SHOW_VERSION.strip()
        bgp = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": "show ip bgp summary"})
        assert not bgp.is_error, result_text(bgp)
        assert result_text(bgp).strip() == SHOW_BGP.strip()
        sessions = fake_device.sessions()
        assert sessions >= 2

        reload = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": "reload"})
        assert reload.is_error
        assert result_text(reload) == gate_error("denied", UPA_SERVER, tool, "no-exec", "EXEC_ARBITRARY", NO_EXEC_REASON)

    assert fake_device.sessions() == sessions
    ran = fake_device.commands()
    assert "reload" not in ran
    assert [c for c in ran if c.startswith("show")] == ["show version", "show ip bgp summary"]
    assert [_drow(x) for x in decision_lines(stderr)] == [
        (tool, "allow", "reads-anywhere", "READ_OPERATIONAL", "downgrade", "true"),
        (tool, "allow", "reads-anywhere", "READ_OPERATIONAL", "downgrade", "true"),
        (tool, "deny", "no-exec", "EXEC_ARBITRARY", "profile", "false"),
    ]


# Row 5 (M1 half): a config dump through the free-form tool, with the words
# separated by any run of spaces and tabs, the tier 1 variants of
# internal/classify (TestConfigReadWhitespace).
CONFIG_DUMPS = ["show running-config", "show  running-config", "show\trunning-config", "\tshow\t\trunning-config\t"]
SHOW_RUN = (REPO / "tests/fixtures/device/transcripts/eos/show_running_config.txt").read_text(encoding="utf-8")
# Tells READ_CONFIG from READ_OPERATIONAL in the decision word.
OPS_ONLY = """version: 1
defaults:
  unknown_target: deny
rules:
  - id: ops-reads
    match: { class: [READ_OPERATIONAL] }
    effect: allow
  - id: no-config-reads
    match: { class: [READ_CONFIG] }
    effect: deny
    reason: "configuration reads are denied in this test policy"
  - id: no-exec
    match: { class: [EXEC_ARBITRARY] }
    effect: deny
    reason: "EXEC_ARBITRARY is denied"
"""


def _transcript_key(command: str) -> str:
    # fake_ssh.transcript_name: what the device looked up.
    return re.sub(r"[^a-z0-9]+", "_", command.strip().lower()).strip("_")


@pytest.mark.asyncio
async def test_row5_config_dump_reclassified_read_config(
    fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path
) -> None:
    """Row 5, M1 half, on upa: `show running-config` through
    send_command_and_get_output, with any spaces or tabs between the words,
    is READ_CONFIG with class_source reclassify (not the downgrade to
    READ_OPERATIONAL a show command gets). Under read-only it is allow by
    `reads-anywhere`. The output is not redacted in M1 (the row's M2 half).

    Only the variants without a tab are sent here. netmiko types the
    command into an interactive shell and waits for its echo, which the
    fake device does not give back for a tab (a real CLI takes a tab as
    completion), so a tab variant ends in netmiko's own timeout after the
    gate has allowed it. The deny test below decides all four variants with
    nothing forwarded, and eos-mcp (eAPI, JSON) carries the tab variants to
    the device (test_eos_mcp.py)."""
    stderr = tmp_path / "fathomgate.stderr"
    tool = "send_command_and_get_output"
    sent = [c for c in CONFIG_DUMPS if "\t" not in c]
    async with LoggedSession(_gated_argv(fathomgate_binary, upa_install, fake_device, tmp_path, "read-only.yaml"), stderr) as session:
        for cmd in sent:
            r = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": cmd})
            assert not r.is_error, (cmd, result_text(r))
            assert result_text(r).strip() == SHOW_RUN.strip(), cmd

    assert [c for c in fake_device.commands() if _transcript_key(c) == "show_running_config"] == sent
    assert [_drow(x) for x in decision_lines(stderr)] == [
        (tool, "allow", "reads-anywhere", "READ_CONFIG", "reclassify", "true") for _ in sent
    ]


@pytest.mark.asyncio
async def test_row5_config_dump_denied_where_config_reads_are(
    fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path
) -> None:
    """Row 5, M1 half, on upa: under a policy that allows READ_OPERATIONAL
    and denies READ_CONFIG, every variant is deny by `no-config-reads` with
    class READ_CONFIG, so the free-form tool is no way round the rule, and
    the device receives none of them. `show version` in the same session is
    allow by `ops-reads`."""
    stderr = tmp_path / "fathomgate.stderr"
    tool = "send_command_and_get_output"
    reason = "configuration reads are denied in this test policy"
    async with LoggedSession(_gated_argv(fathomgate_binary, upa_install, fake_device, tmp_path, OPS_ONLY), stderr) as session:
        for cmd in CONFIG_DUMPS:
            r = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": cmd})
            assert r.is_error, cmd
            assert result_text(r) == gate_error("denied", UPA_SERVER, tool, "no-config-reads", "READ_CONFIG", reason)
        assert fake_device.sessions() == 0
        ok = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "command": "show version"})
        assert not ok.is_error, result_text(ok)

    assert [c for c in fake_device.commands() if c.strip().startswith("show")] == ["show version"]
    assert [_drow(x) for x in decision_lines(stderr)] == [
        *[(tool, "deny", "no-config-reads", "READ_CONFIG", "reclassify", "false") for _ in CONFIG_DUMPS],
        (tool, "allow", "ops-reads", "READ_OPERATIONAL", "downgrade", "true"),
    ]


@pytest.mark.asyncio
async def test_config_lines_leaving_config_mode_denied_as_exec(
    fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path
) -> None:
    """set_config_commands_and_commit_or_save with ["end", "reload now"]:
    netmiko's send_config_set would type both into the shell, and `end`
    leaves configuration mode, so `reload now` would run in exec mode. The
    call is EXEC_ARBITRARY (M1-36) and read-only denies it by `no-exec`; a
    plain config line is WRITE_CONFIG and denied by `no-writes`. Neither
    opens an SSH session."""
    stderr = tmp_path / "fathomgate.stderr"
    tool = "set_config_commands_and_commit_or_save"
    async with LoggedSession(_gated_argv(fathomgate_binary, upa_install, fake_device, tmp_path, "read-only.yaml"), stderr) as session:
        exec_ = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "commands": ["end", "reload now"]})
        write = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": DEVICE, "commands": ["hostname FAKE-lab-01"]})

    assert exec_.is_error and result_text(exec_) == gate_error("denied", UPA_SERVER, tool, "no-exec", "EXEC_ARBITRARY", NO_EXEC_REASON)
    assert write.is_error and result_text(write) == gate_error("denied", UPA_SERVER, tool, "no-writes", "WRITE_CONFIG", NO_WRITES_REASON)
    assert fake_device.sessions() == 0
    assert fake_device.commands() == []
    assert [(x["decision"], x["rule_id"], x["class"], x["forwarded"]) for x in decision_lines(stderr)] == [
        ("deny", "no-exec", "EXEC_ARBITRARY", "false"),
        ("deny", "no-writes", "WRITE_CONFIG", "false"),
    ]


@pytest.mark.asyncio
async def test_unknown_device_name_denied(fathomgate_binary: Path, upa_install: UpaInstall, fake_device: FakeDevice, tmp_path: Path) -> None:
    """Row 6's rule on upa (supporting evidence: the row names
    netdev-ssh-mcp, which has no write tool): a device name fathomgate's
    inventory does not list is deny by `default:unknown_target` for a read,
    a write and exec alike, and the decision line says it was not
    forwarded. `core-x` is in upa's own TOML and points at the fake device,
    so a forwarded call would connect and run there; the device logs no
    session and no command."""
    stderr = tmp_path / "fathomgate.stderr"
    calls = [
        ("send_command_and_get_output", "READ_OPERATIONAL", {"command": "show version"}),
        ("send_command_and_get_output", "EXEC_ARBITRARY", {"command": "reload"}),
        ("set_config_commands_and_commit_or_save", "WRITE_CONFIG", {"commands": ["hostname FAKE-x"]}),
    ]
    argv = _gated_argv(fathomgate_binary, upa_install, fake_device, tmp_path, "read-only.yaml", upa_extra=("core-x",))
    async with LoggedSession(argv, stderr) as session:
        for tool, cls, extra in calls:
            r = await session.call_tool(f"{UPA_SERVER}.{tool}", {"name": "core-x", **extra})
            assert r.is_error
            assert result_text(r) == gate_error("denied", UPA_SERVER, tool, "default:unknown_target", cls, UNKNOWN_TARGET_REASON)
    assert fake_device.sessions() == 0
    assert fake_device.commands() == []
    assert [(x["tool"], x["decision"], x["rule_id"], x["class"], x["unknown_target"], x["forwarded"]) for x in decision_lines(stderr)] == [
        (tool, "deny", "default:unknown_target", cls, "true", "false") for tool, cls, _ in calls
    ]
