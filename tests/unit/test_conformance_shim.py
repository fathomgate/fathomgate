# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 1: tests/conformance/shim.py, the auth-and-prefix shim the
conformance suite drives `fathomgate serve --listen` through (T0.32,
ADR 0016).

The shim is test harness, so a bug in it could hide a fathomgate failure or
invent one. These tests pin the two rewrites it may make (the bearer token,
and `conf.` on an unprefixed tools/call name in `params.name` and `Mcp-Name`)
and that everything else crosses unchanged: other bodies byte for byte,
Host, status, response headers, and an SSE stream as it arrives, including
its end when the client leaves. The target is a small recording HTTP server,
so no fathomgate, Go or Node is needed.
"""

from __future__ import annotations

import base64
import http.client
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "conformance"))
import shim

pytestmark = pytest.mark.tier1

TOKEN = "FAKE-shim-token-0123456789abcdef0123456789"


class Target:
    """Records each request; answers by path:
    /mcp      200 JSON with Content-Length and Mcp-Session-Id
    /sse      200 SSE, one event, waits for `release`, a second event
    /hold     200 SSE, one event, then waits for the client side to close
    /deny     401 with WWW-Authenticate
    """

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.release = threading.Event()
        self.hold_closed = threading.Event()
        target = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args) -> None:
                pass

            def _any(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                target.requests.append(
                    {"method": self.command, "path": self.path, "headers": list(self.headers.items()), "body": body}
                )
                if self.path == "/deny":
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", "Bearer")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path in ("/sse", "/hold"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Mcp-Session-Id", "FAKE-session")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.close_connection = True
                    self.wfile.write(b"event: message\ndata: {\"n\":1}\n\n")
                    self.wfile.flush()
                    if self.path == "/sse":
                        target.release.wait(10)
                        self.wfile.write(b"event: message\ndata: {\"n\":2}\n\n")
                        self.wfile.flush()
                        return
                    # /hold: block until the shim closes the upstream side.
                    self.connection.settimeout(10)
                    try:
                        if self.connection.recv(1) == b"":
                            target.hold_closed.set()
                    except OSError:
                        target.hold_closed.set()
                    return
                payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Mcp-Session-Id", "FAKE-session")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_DELETE = _any

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True).start()
        self.port = self.httpd.server_address[1]

    def header(self, i: int, name: str) -> list[str]:
        return [v for k, v in self.requests[i]["headers"] if k.lower() == name.lower()]

    def stop(self) -> None:
        self.release.set()
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def target():
    t = Target()
    yield t
    t.stop()


def start_shim(target: Target, prefix: str, token: str) -> tuple[int, ThreadingHTTPServer]:
    httpd = shim.serve(f"http://127.0.0.1:{target.port}/mcp", prefix, token)
    threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True).start()
    return httpd.server_address[1], httpd


@pytest.fixture
def fg_shim(target):
    """The fathomgate-leg shim: prefix conf, a token."""
    port, httpd = start_shim(target, "conf", TOKEN)
    yield port
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def control_shim(target):
    """The control-leg shim: no prefix, no token."""
    port, httpd = start_shim(target, "", "")
    yield port
    httpd.shutdown()
    httpd.server_close()


def send(port: int, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    h.update(headers or {})
    conn.request(method, path, body=body, headers=h)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp, data


def call(name: str, **extra) -> bytes:
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": name, "arguments": {"a": 1}, **extra}}
    return json.dumps(msg, indent=1).encode()


# --- the two rewrites -------------------------------------------------------


def test_token_added_and_replaces_the_clients(target, fg_shim):
    send(fg_shim, "POST", "/mcp", b"{}")
    send(fg_shim, "POST", "/mcp", b"{}", {"Authorization": "Bearer FAKE-from-the-suite"})
    assert target.header(0, "Authorization") == [f"Bearer {TOKEN}"]
    assert target.header(1, "Authorization") == [f"Bearer {TOKEN}"]


def test_no_token_no_header(target, control_shim):
    send(control_shim, "POST", "/mcp", b"{}")
    assert target.header(0, "Authorization") == []


def test_unprefixed_tools_call_name_gets_prefix(target, fg_shim):
    send(fg_shim, "POST", "/mcp", call("test_simple_text", _meta={"k": "v"}))
    got = json.loads(target.requests[0]["body"])
    assert got["params"]["name"] == "conf.test_simple_text"
    # Nothing else in the message changes.
    assert got == {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "conf.test_simple_text", "arguments": {"a": 1}, "_meta": {"k": "v"}},
    }
    assert target.header(0, "Content-Length") == [str(len(target.requests[0]["body"]))]


@pytest.mark.parametrize(
    "body",
    [
        call("conf.test_simple_text"),  # already prefixed
        call("other.tool"),  # any dot: left alone
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, indent=2).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "p"}}).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"name": "x"}}).encode(),  # a response
        json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "t"}}]).encode(),
        b"{not json",
        b"",
    ],
)
def test_other_bodies_cross_byte_for_byte(target, fg_shim, body):
    send(fg_shim, "POST", "/mcp", body)
    assert target.requests[0]["body"] == body


def test_mcp_name_prefixed_on_tools_call_only(target, fg_shim):
    send(fg_shim, "POST", "/mcp", call("t"), {"Mcp-Method": "tools/call", "Mcp-Name": "t"})
    send(fg_shim, "POST", "/mcp", b"{}", {"Mcp-Method": "prompts/get", "Mcp-Name": "p"})
    send(fg_shim, "POST", "/mcp", b"{}", {"Mcp-Method": "tools/call", "Mcp-Name": "conf.t"})
    assert target.header(0, "Mcp-Name") == ["conf.t"]
    assert target.header(1, "Mcp-Name") == ["p"]
    assert target.header(2, "Mcp-Name") == ["conf.t"]


def test_tools_call_body_under_another_mcp_method_keeps_names_matched(target, fg_shim):
    # tasks-headers-reject-mismatched-method: the suite sends a tools/call
    # body with a different Mcp-Method to test the method check only. The
    # names must still match, so Mcp-Name is prefixed with the body's name.
    send(fg_shim, "POST", "/mcp", call("greet"), {"Mcp-Method": "tasks/get", "Mcp-Name": "greet"})
    assert json.loads(target.requests[0]["body"])["params"]["name"] == "conf.greet"
    assert target.header(0, "Mcp-Name") == ["conf.greet"]
    assert target.header(0, "Mcp-Method") == ["tasks/get"]


def test_tools_call_body_without_mcp_method_keeps_names_matched(target, fg_shim):
    send(fg_shim, "POST", "/mcp", call("greet"), {"Mcp-Name": "greet"})
    assert json.loads(target.requests[0]["body"])["params"]["name"] == "conf.greet"
    assert target.header(0, "Mcp-Name") == ["conf.greet"]
    assert target.header(0, "Mcp-Method") == []


def test_other_method_in_header_and_body_leaves_mcp_name(target, fg_shim):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"taskId": "t1"}}).encode()
    send(fg_shim, "POST", "/mcp", body, {"Mcp-Method": "tasks/get", "Mcp-Name": "t1"})
    assert target.header(0, "Mcp-Name") == ["t1"]
    assert target.requests[0]["body"] == body


@pytest.mark.parametrize(
    ("name", "want"),
    [("t", "conf.t"), ("", ""), ("conf.t", "conf.t"), ("=?base64?dA==?=", "=?base64?dA==?=")],
)
def test_prefixed(name, want):
    assert shim.prefixed(name, "conf") == want
    assert shim.prefixed(name, "") == name


def test_deliberate_mismatch_stays_a_mismatch(target, fg_shim):
    send(fg_shim, "POST", "/mcp", call("a"), {"Mcp-Method": "tools/call", "Mcp-Name": "b"})
    assert json.loads(target.requests[0]["body"])["params"]["name"] == "conf.a"
    assert target.header(0, "Mcp-Name") == ["conf.b"]


def test_base64_mcp_name_left_alone(target, fg_shim):
    enc = "=?base64?" + base64.b64encode(b"t").decode() + "?="
    send(fg_shim, "POST", "/mcp", b"{}", {"Mcp-Method": "tools/call", "Mcp-Name": enc})
    assert target.header(0, "Mcp-Name") == [enc]


def test_control_shim_changes_nothing(target, control_shim):
    body = call("test_simple_text")
    send(control_shim, "POST", "/mcp", body, {"Mcp-Method": "tools/call", "Mcp-Name": "test_simple_text"})
    assert target.requests[0]["body"] == body
    assert target.header(0, "Mcp-Name") == ["test_simple_text"]


# --- pass-through -------------------------------------------------------------


def test_request_line_and_headers_pass_through(target, fg_shim):
    send(
        fg_shim,
        "DELETE",
        "/mcp?x=1",
        headers={"Host": "evil.example.com", "Origin": "http://evil.example.com", "Mcp-Session-Id": "FAKE-s"},
    )
    r = target.requests[0]
    assert (r["method"], r["path"]) == ("DELETE", "/mcp?x=1")
    # Host as the suite sent it, so the DNS-rebinding probe is not masked.
    assert target.header(0, "Host") == ["evil.example.com"]
    assert target.header(0, "Origin") == ["http://evil.example.com"]
    assert target.header(0, "Mcp-Session-Id") == ["FAKE-s"]


def test_status_and_response_headers_pass_through(target, fg_shim):
    resp, data = send(fg_shim, "POST", "/deny", b"{}")
    assert resp.status == 401
    assert resp.getheader("WWW-Authenticate") == "Bearer"
    resp, data = send(fg_shim, "POST", "/mcp", b"{}")
    assert resp.status == 200
    assert resp.getheader("Mcp-Session-Id") == "FAKE-session"
    assert json.loads(data) == {"jsonrpc": "2.0", "id": 1, "result": {}}


def test_sse_is_streamed_as_it_arrives(target, fg_shim):
    conn = http.client.HTTPConnection("127.0.0.1", fg_shim, timeout=10)
    conn.request("POST", "/sse", body=b"{}", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 200
    assert resp.getheader("Content-Type") == "text/event-stream"
    assert resp.getheader("Mcp-Session-Id") == "FAKE-session"
    # The first event arrives while the target still holds the second back.
    first = b""
    while b"\n\n" not in first:
        first += resp.read1(1024)
    assert b'data: {"n":1}' in first
    target.release.set()
    rest = resp.read()
    assert b'data: {"n":2}' in rest
    conn.close()


def test_client_leaving_ends_the_upstream_stream(target, fg_shim):
    sock = socket.create_connection(("127.0.0.1", fg_shim), timeout=10)
    sock.sendall(b"GET /hold HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n")
    got = b""
    while b'data: {"n":1}' not in got:
        got += sock.recv(1024)
    sock.close()
    assert target.hold_closed.wait(5), "the shim kept the upstream stream open after the client left"


def test_token_is_never_logged(target, fg_shim, capfd):
    send(fg_shim, "POST", "/mcp", call("t"))
    send(fg_shim, "POST", "/deny", b"{}")
    out, err = capfd.readouterr()
    assert "POST /mcp" in err  # the request line is logged ...
    assert TOKEN not in out + err  # ... the token never


def test_unreachable_target_gets_502():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]  # closed again before the shim connects
    httpd = shim.serve(f"http://127.0.0.1:{dead}/mcp", "conf", TOKEN)
    threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True).start()
    try:
        resp, data = send(httpd.server_address[1], "POST", "/mcp", b"{}")
        assert resp.status == 502
        assert TOKEN.encode() not in data
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize("framing", [b"zz\r\n{}\r\n0\r\n\r\n", b"-1\r\n{}\r\n0\r\n\r\n"])
def test_malformed_chunked_body_gets_400(target, fg_shim, framing):
    sock = socket.create_connection(("127.0.0.1", fg_shim), timeout=10)
    sock.sendall(b"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n" + framing)
    got = sock.recv(1024)
    sock.close()
    assert got.startswith(b"HTTP/1.1 400 ")
    assert target.requests == []


def test_target_must_be_http_with_a_port():
    with pytest.raises(ValueError):
        shim.make_handler("https://127.0.0.1:1/mcp", "", "")
    with pytest.raises(ValueError):
        shim.make_handler("http://127.0.0.1/mcp", "", "")
