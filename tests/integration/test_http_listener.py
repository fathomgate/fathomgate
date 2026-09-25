# SPDX-License-Identifier: Apache-2.0
"""Tier 2, matrix row 23: `fathomgate serve --listen` (Streamable HTTP toward
the agent, ADR 0016 as amended by ADR 0023) in front of the real
krisiasty/netdev-ssh-mcp (pinned in conftest), with the fake SSH device.

A real MCP client, the python-sdk `mcp` 2.2.0 over Streamable HTTP with a
bearer token, in both protocol eras:

- 2025-11-25: the initialize handshake (`mode="legacy"`), a stateful session;
- 2026-07-28: `server/discover` (`mode="auto"`), stateless requests.

Each lists the prefixed tools and runs a read-only `show version` on the fake
device, on both loopback URLs the `listening` lines print. Raw HTTP requests
check the refusals: 401 with no token and with a wrong one, 403 with an
`Origin` header or a non-loopback `Host`, and a `tools/call` with no token
or a wrong one reaches no device. Every case also checks that the
token never reaches fathomgate's stderr, and that nothing is written to
stdout (the listener and stdio are exclusive).

The token is FAKE and random per run, from an owner-only file
(`--listen-token-file`, the route docs/install.md leads with) or from
`FATHOMGATE_LISTEN_TOKEN`. What the upstream returns is data: the tests
compare it and never act on it.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import REPO, SERVER, FakeDevice, client_env, serve_args

pytestmark = [pytest.mark.tier2, pytest.mark.netdev_ssh_mcp]

UPSTREAM_TOOLS = {"get_config", "run_ping", "run_show_command", "run_traceroute", "trust_host_key"}
TRANSCRIPT = REPO / "tests/fixtures/device/transcripts/eos/show_version.txt"
PRINCIPAL = "ci"

# The two protocol eras and how the python-sdk client reaches each one.
ERAS = {
    "2025-11-25": "legacy",  # initialize handshake, Mcp-Session-Id
    "2026-07-28": "auto",  # server/discover, then stateless requests
}

LISTENING = re.compile(r"msg=listening url=(\S+)")
REQUIRED = os.environ.get("FATHOMGATE_TIER2_REQUIRED") == "1"


def _fake_token() -> str:
    """A FAKE bearer token: 69 bytes of printable ASCII, 256 random bits."""
    return "FAKE-" + secrets.token_hex(32)


def _owner_only_file(path: Path, content: str) -> None:
    """Write `content` to a new file only the current user can read, the way
    docs/install.md step 1 does: mode 0600 on Unix (umask 077), and on Windows
    a protected DACL granting the user alone (`icacls /inheritance:r
    /grant:r %USERNAME%:F`)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as f:
        f.write(content + "\n")
    if sys.platform == "win32":
        user = os.environ["USERNAME"]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"], check=True, capture_output=True)


@dataclass
class Listener:
    """A running `fathomgate serve --listen` and what it printed."""

    proc: subprocess.Popen
    token: str
    principal: str  # `ci` for the token file, `env` for FATHOMGATE_LISTEN_TOKEN
    urls: list[str]
    stderr: list[str] = field(default_factory=list)
    stdout: list[str] = field(default_factory=list)
    _threads: list[threading.Thread] = field(default_factory=list)

    def stop(self) -> tuple[int, str]:
        """Stop it the way an operator does (Ctrl+C: SIGINT on Unix,
        CTRL_BREAK_EVENT on Windows, which Go delivers as os.Interrupt) and
        return the exit status and the whole of stderr."""
        if self.proc.poll() is None:
            if sys.platform == "win32":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        for t in self._threads:
            t.join(timeout=10)
        return self.proc.returncode, "".join(self.stderr)


def _pump(stream, sink: list[str], seen: threading.Event | None = None) -> None:
    for line in iter(stream.readline, ""):
        sink.append(line)
        if seen is not None and LISTENING.search(line):
            seen.set()
    stream.close()


def _start_listener(fathomgate: Path, upstream: Path, device: FakeDevice, tmp_path: Path, source: str) -> Listener:
    token = _fake_token()
    env = client_env(dict(os.environ))
    env.pop("FATHOMGATE_LISTEN_TOKEN", None)
    env.pop("MCPGODEBUG", None)
    listen = ["--listen", "127.0.0.1:0"]
    if source == "file":
        token_file = tmp_path / "agent.token"
        _owner_only_file(token_file, token)
        listen += ["--listen-token-file", f"{PRINCIPAL}={token_file}"]
    else:
        env["FATHOMGATE_LISTEN_TOKEN"] = token
    argv = [str(fathomgate), *serve_args(upstream, device)]
    argv[2:2] = listen  # after "serve", before the upstream flags
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )
    lst = Listener(proc=proc, token=token, principal=PRINCIPAL if source == "file" else "env", urls=[])
    seen = threading.Event()
    for stream, sink, ev in ((proc.stderr, lst.stderr, seen), (proc.stdout, lst.stdout, None)):
        t = threading.Thread(target=_pump, args=(stream, sink, ev), daemon=True)
        t.start()
        lst._threads.append(t)
    # One `listening` line per bound address, the address asked for first
    # (ADR 0023). Wait for the upstream to be ready and both lines to appear.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and proc.poll() is None:
        text = "".join(lst.stderr)
        urls = LISTENING.findall(text)
        if len(urls) >= 2 or (len(urls) == 1 and "listening on one address only" in text):
            break
        time.sleep(0.05)
    lst.urls = LISTENING.findall("".join(lst.stderr))
    if not lst.urls:
        code, err = lst.stop()
        pytest.fail(f"fathomgate serve --listen printed no listening line (exit {code}):\n{err}")
    return lst


@pytest.fixture(params=["file", "env"], ids=["token-file", "token-env"])
def listener(request, fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> Iterator[Listener]:
    lst = _start_listener(fathomgate_binary, upstream_binary, fake_device, tmp_path, request.param)
    try:
        yield lst
    finally:
        lst.stop()


@pytest.fixture
def file_listener(fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path) -> Iterator[Listener]:
    lst = _start_listener(fathomgate_binary, upstream_binary, fake_device, tmp_path, "file")
    try:
        yield lst
    finally:
        lst.stop()


def _both_urls(lst: Listener) -> list[str]:
    """Both loopback URLs, `127.0.0.1` first. On a host with no IPv6
    loopback fathomgate serves one family and says so; that skips the
    `[::1]` half locally, and fails where tier 2 is required (CI)."""
    hosts = [urlsplit(u).hostname for u in lst.urls]
    if hosts == ["127.0.0.1", "::1"]:
        return lst.urls
    msg = f"expected listening URLs on 127.0.0.1 then [::1], got {lst.urls}"
    if REQUIRED or len(lst.urls) != 1:
        pytest.fail(msg + "\n" + "".join(lst.stderr))
    pytest.skip(msg + " (no IPv6 loopback on this host)")


def _assert_token_kept_out(lst: Listener, *also: str) -> str:
    """Stop fathomgate and check what it wrote: exit 0 on the signal, a
    `shutting down` line, nothing on stdout, and neither the token nor any
    other presented credential anywhere in stderr."""
    code, err = lst.stop()
    assert code == 0, err
    assert 'msg="shutting down"' in err, err
    assert "".join(lst.stdout) == "", "fathomgate wrote to stdout with --listen"
    for secret in (lst.token, lst.token.removeprefix("FAKE-"), *also):
        assert secret not in err, "a bearer token reached fathomgate's stderr"
    return err


def _text(result) -> str:
    return "".join(getattr(c, "text", "") or "" for c in result.content)


async def _list_and_show(url: str, token: str, era: str, port: int):
    """Connect the python-sdk client over Streamable HTTP with the token, in
    one era; return the negotiated version, the tool names and the
    `show version` result."""
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
    async with http, Client(streamable_http_client(url, http_client=http), mode=ERAS[era]) as client:
        tools = (await client.list_tools()).tools
        result = await client.call_tool(
            f"{SERVER}.run_show_command",
            {"host": "127.0.0.1", "port": port, "device_type": "eos", "command": "show version"},
        )
        return client.protocol_version, [t.name for t in tools], result


@pytest.mark.parametrize("era", list(ERAS))
@pytest.mark.asyncio
async def test_http_tools_list_and_show_version(listener: Listener, fake_device: FakeDevice, era: str) -> None:
    """Row 23: over Streamable HTTP with the bearer token, in each era, the
    agent sees exactly the upstream's tools as `netdev-ssh-mcp.<tool>`, and a
    read-only `show version` reaches the fake device once and comes back
    unchanged (M0 forwards; no policy, no redaction)."""
    version, names, result = await _list_and_show(listener.urls[0], listener.token, era, fake_device.port)

    assert version == era
    assert sorted(names) == sorted(f"{SERVER}.{t}" for t in UPSTREAM_TOOLS)
    assert not result.is_error, _text(result)
    assert _text(result).strip() == TRANSCRIPT.read_text().strip()
    assert fake_device.commands() == ["show version"]
    err = _assert_token_kept_out(listener)
    # The principal is logged by its name, never by its token.
    assert re.search(rf"msg=listening url=\S+ server={re.escape(SERVER)} principals={listener.principal} ", err), err


@pytest.mark.asyncio
async def test_http_both_listening_urls(file_listener: Listener, fake_device: FakeDevice) -> None:
    """Row 23, ADR 0023: fathomgate prints one `listening` line per loopback
    family on the same port, and a client pasting either URL gets the tools
    and a `show version`, in both eras."""
    urls = _both_urls(file_listener)
    assert len({urlsplit(u).port for u in urls}) == 1, urls
    assert all(urlsplit(u).path == "/mcp" for u in urls), urls

    for url in urls:
        for era in ERAS:
            version, names, result = await _list_and_show(url, file_listener.token, era, fake_device.port)
            assert version == era, url
            assert sorted(names) == sorted(f"{SERVER}.{t}" for t in UPSTREAM_TOOLS), url
            assert not result.is_error, (url, _text(result))
            assert _text(result).strip() == TRANSCRIPT.read_text().strip()

    assert fake_device.commands() == ["show version"] * (len(urls) * len(ERAS))
    _assert_token_kept_out(file_listener)


# --- refusals, as raw HTTP -----------------------------------------------------

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fathomgate-tier2", "version": "0"}},
}
TOOLS_LIST_2026 = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": {"name": "fathomgate-tier2", "version": "0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    },
}
BASE_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
HEADERS_2026 = {**BASE_HEADERS, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/list"}


@dataclass
class Reply:
    status: int
    headers: dict[str, str]
    body: str


def _post(url: str, body: dict, headers: dict[str, str]) -> Reply:
    u = urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=20)
    try:
        conn.request("POST", u.path, body=json.dumps(body), headers=headers)
        resp = conn.getresponse()
        headers_ = {k.lower(): v for k, v in resp.getheaders()}
        if resp.status != 200 or not headers_.get("content-type", "").startswith("text/event-stream"):
            return Reply(resp.status, headers_, resp.read().decode())
        # An SSE stream: read events up to the JSON-RPC response (a stateful
        # GET-less stream may stay open after it).
        lines: list[str] = []
        for raw in iter(resp.readline, b""):
            line = raw.decode()
            lines.append(line)
            if line.startswith("data:") and ('"result"' in line or '"error"' in line):
                break
        return Reply(resp.status, headers_, "".join(lines))
    finally:
        conn.close()


def _wrong_token(token: str) -> str:
    """A FAKE token of the same length and shape that is not the configured one."""
    while True:
        wrong = _fake_token()
        if wrong != token:
            return wrong


@pytest.mark.parametrize(
    ("body", "headers"),
    [(INITIALIZE, BASE_HEADERS), (TOOLS_LIST_2026, HEADERS_2026)],
    ids=["2025-11-25", "2026-07-28"],
)
def test_http_refusals(file_listener: Listener, fake_device: FakeDevice, body: dict, headers: dict[str, str]) -> None:
    """Row 23: on both loopback URLs, in each era's request shape, a request
    with no token or a wrong one gets 401 `WWW-Authenticate: Bearer`, and one
    with an `Origin` header gets 403, with the right token or none (Origin is
    checked before authentication), as does a non-loopback `Host`. Each
    refusal closes the connection and names no token. The same request with
    the right token and no Origin is answered 200, so the refusals are not a
    broken request. Nothing reaches the device, and the failed attempts are
    logged without their tokens."""
    token = file_listener.token
    wrong = _wrong_token(token)
    # Locally, a host with no IPv6 loopback still checks the one URL it has.
    urls = file_listener.urls if len(file_listener.urls) == 1 and not REQUIRED else _both_urls(file_listener)
    for url in urls:
        ok = _post(url, body, {**headers, "Authorization": f"Bearer {token}"})
        assert ok.status == 200, (url, ok)
        assert "event: message" in ok.body or '"result"' in ok.body, (url, ok)

        cases = {
            "no token": (401, headers),
            "wrong token": (401, {**headers, "Authorization": f"Bearer {wrong}"}),
            "not a bearer token": (401, {**headers, "Authorization": f"Basic {token}"}),
            "Origin with token": (403, {**headers, "Authorization": f"Bearer {token}", "Origin": "http://evil.example"}),
            "Origin without token": (403, {**headers, "Origin": "http://evil.example"}),
            # DNS rebinding: a page's name resolved to loopback. Checked
            # before authentication too.
            "non-loopback Host": (403, {**headers, "Authorization": f"Bearer {token}", "Host": "evil.example"}),
            "non-loopback Host without token": (403, {**headers, "Host": "evil.example"}),
        }
        for name, (want, hdrs) in cases.items():
            r = _post(url, body, hdrs)
            assert r.status == want, (url, name, r)
            assert r.headers.get("connection", "").lower() == "close", (url, name, r.headers)
            assert "access-control-allow-origin" not in r.headers, (url, name, r.headers)
            if want == 401:
                assert r.headers.get("www-authenticate", "").startswith("Bearer"), (url, name, r.headers)
            for secret in (token, wrong):
                assert secret not in r.body and secret not in json.dumps(r.headers), (url, name)

    assert fake_device.commands() == []
    err = _assert_token_kept_out(file_listener, wrong)
    # At least one failed attempt is logged with its reason (rate-limited to
    # one line a second, so not one per request).
    assert re.search(r'msg="listener: authentication failed" remote=\S+ reason="(no Authorization header|unknown token|not a bearer token)"', err), err


# --- unauthenticated tool calls ---------------------------------------------------

SHOW_VERSION = "show version"


def _call_body(port: int, meta: dict | None = None) -> dict:
    params: dict = {
        "name": f"{SERVER}.run_show_command",
        "arguments": {"host": "127.0.0.1", "port": port, "device_type": "eos", "command": SHOW_VERSION},
    }
    if meta:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params}


def _session_2025(url: str, token: str) -> dict[str, str]:
    """Open a 2025-11-25 session with the token; return the headers a later
    request on it carries (without Authorization)."""
    auth = {"Authorization": f"Bearer {token}"}
    init = _post(url, INITIALIZE, {**BASE_HEADERS, **auth})
    assert init.status == 200, init
    sid = init.headers.get("mcp-session-id")
    assert sid, init.headers
    headers = {**BASE_HEADERS, "Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"}
    note = _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, {**headers, **auth})
    assert note.status == 202, note
    return headers


@pytest.mark.parametrize("era", list(ERAS))
def test_http_tool_call_needs_token(file_listener: Listener, fake_device: FakeDevice, era: str) -> None:
    """Row 23 (security review L3): a `tools/call` of `run_show_command` with
    no token or a wrong one gets 401 and sends nothing to the device, so an
    authentication bypass would show up as a device command. In the 2025 era
    the call goes on a session the right token opened, so the check is per
    request, not per session. A control call with the token runs
    `show version` once, so the request shape does reach the device."""
    url = file_listener.urls[0]
    token = file_listener.token
    wrong = _wrong_token(token)
    if era == "2025-11-25":
        headers = _session_2025(url, token)
        body = _call_body(fake_device.port)
    else:
        headers = {**BASE_HEADERS, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": f"{SERVER}.run_show_command"}
        body = _call_body(fake_device.port, TOOLS_LIST_2026["params"]["_meta"])

    for name, hdrs in {
        "no token": headers,
        "wrong token": {**headers, "Authorization": f"Bearer {wrong}"},
    }.items():
        r = _post(url, body, hdrs)
        assert r.status == 401, (name, r)
        assert r.headers.get("www-authenticate", "").startswith("Bearer"), (name, r.headers)
    assert fake_device.commands() == []

    ok = _post(url, body, {**headers, "Authorization": f"Bearer {token}"})
    assert ok.status == 200, ok
    assert "FAKE0000SN01" in ok.body, ok.body
    assert fake_device.commands() == [SHOW_VERSION]
    _assert_token_kept_out(file_listener, wrong)
