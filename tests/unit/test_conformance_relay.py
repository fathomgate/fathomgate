"""Tier 1: tests/conformance/relay.py, the Streamable HTTP front the
conformance suite drives fathomgate through (T0.4).

The relay is test harness, so a bug in it could hide a fathomgate failure or
invent one. These tests pin the two message rewrites it is allowed to make
(request ids, and the tool-name prefix on tools/call only) and the HTTP
behaviour the suite relies on. The child is a tiny stdio echo server, so no
fathomgate, Go or Node is needed.
"""

from __future__ import annotations

import http.client
import json
import sys
import textwrap
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "conformance"))
import relay  # noqa: E402

pytestmark = pytest.mark.tier1

# Answers every request with {"echo": <request>}. Before answering a request
# that carries a progressToken it sends one notifications/progress, and before
# answering "listen" it sends a notification tagged with the request's id as
# go-sdk does for subscriptions/listen.
ECHO_CHILD = textwrap.dedent(
    """
    import json, sys
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg or "method" not in msg:
            continue
        meta = (msg.get("params") or {}).get("_meta") or {}
        if "progressToken" in meta:
            note = {"jsonrpc": "2.0", "method": "notifications/progress",
                    "params": {"progressToken": meta["progressToken"], "progress": 1}}
            print(json.dumps(note), flush=True)
        if msg["method"] == "listen":
            note = {"jsonrpc": "2.0", "method": "notifications/subscriptions/acknowledged",
                    "params": {"_meta": {relay.SUBSCRIPTION_ID: msg["id"]}}}
            print(json.dumps(note), flush=True)
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg}}), flush=True)
    """
).replace("relay.SUBSCRIPTION_ID", repr(relay.SUBSCRIPTION_ID))


@pytest.fixture
def server(tmp_path: Path):
    child = tmp_path / "echo_child.py"
    child.write_text(ECHO_CHILD)
    r = relay.Relay([sys.executable, str(child)], tool_prefix="conf")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), relay.make_handler(r, "/mcp"))
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd.server_address[1]
    httpd.shutdown()
    r.stop()
    httpd.server_close()


def post(port: int, body, headers: dict[str, str] | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    h.update(headers or {})
    conn.request("POST", "/mcp", body=json.dumps(body), headers=h)
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    events = [json.loads(line[len("data: "):]) for line in data.splitlines() if line.startswith("data: ")]
    return resp, events


@pytest.mark.parametrize(
    "value, ok",
    [
        ("127.0.0.1:3001", True),
        ("localhost", True),
        ("[::1]:8080", True),
        ("http://localhost:3001", True),
        ("evil.example.com", False),
        ("http://evil.example.com", False),
        ("127.0.0.1.evil.example.com", False),
        ("", False),
    ],
)
def test_loopback_host(value: str, ok: bool) -> None:
    assert relay.loopback_host(value) is ok


def test_adapt_prefixes_only_unprefixed_tools_call() -> None:
    r = relay.Relay(["true"], tool_prefix="conf")
    call = {"method": "tools/call", "params": {"name": "test_simple_text"}}
    r.adapt(call)
    assert call["params"]["name"] == "conf.test_simple_text"
    already = {"method": "tools/call", "params": {"name": "conf.test_simple_text"}}
    r.adapt(already)
    assert already["params"]["name"] == "conf.test_simple_text"
    prompt = {"method": "prompts/get", "params": {"name": "test_simple_prompt"}}
    r.adapt(prompt)
    assert prompt["params"]["name"] == "test_simple_prompt"


def test_adapt_without_prefix_is_a_no_op() -> None:
    r = relay.Relay(["true"], tool_prefix="")
    call = {"method": "tools/call", "params": {"name": "test_simple_text"}}
    r.adapt(call)
    assert call["params"]["name"] == "test_simple_text"


def test_initialize_opens_a_session_and_ids_round_trip(server: int) -> None:
    resp, events = post(server, {"jsonrpc": "2.0", "id": "init-1", "method": "initialize", "params": {}})
    assert resp.status == 200
    assert resp.getheader("Content-Type") == "text/event-stream"
    sid = resp.getheader(relay.SESSION_HEADER)
    assert sid
    assert events[-1]["id"] == "init-1"
    # The child saw a relay id, not the client's.
    assert events[-1]["result"]["echo"]["id"] != "init-1"

    resp, events = post(
        server,
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "test_simple_text"}},
        {relay.SESSION_HEADER: sid},
    )
    assert resp.status == 200
    assert events[-1]["id"] == 7
    assert events[-1]["result"]["echo"]["params"]["name"] == "conf.test_simple_text"


def test_notification_gets_202(server: int) -> None:
    _, _ = post(server, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    resp, events = post(server, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert resp.status == 202
    assert events == []


def test_progress_is_streamed_before_the_response(server: int) -> None:
    body = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "x", "_meta": {"progressToken": "tok"}}}
    resp, events = post(server, body)
    assert resp.status == 200
    assert [e.get("method") for e in events] == ["notifications/progress", None]
    assert events[0]["params"]["progressToken"] == "tok"
    assert events[1]["id"] == 3


def test_subscription_tag_gets_the_client_id(server: int) -> None:
    resp, events = post(server, {"jsonrpc": "2.0", "id": "sub-9", "method": "listen", "params": {}})
    assert resp.status == 200
    assert events[0]["method"] == "notifications/subscriptions/acknowledged"
    assert events[0]["params"]["_meta"][relay.SUBSCRIPTION_ID] == "sub-9"
    assert events[1]["id"] == "sub-9"


def test_http_errors(server: int) -> None:
    resp, _ = post(server, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {relay.SESSION_HEADER: "nope"})
    assert resp.status == 404
    resp, _ = post(server, {"jsonrpc": "2.0", "id": 1, "method": "ping"}, {"Host": "evil.example.com"})
    assert resp.status == 403
    conn = http.client.HTTPConnection("127.0.0.1", server, timeout=10)
    conn.request("GET", "/mcp")
    get = conn.getresponse()
    get.read()
    conn.close()
    assert get.status == 405
    assert get.getheader("Allow") == "POST, DELETE"
