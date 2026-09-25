# SPDX-License-Identifier: Apache-2.0
"""Streamable HTTP front for a stdio MCP server, for the conformance suite.

The official MCP conformance suite (@modelcontextprotocol/conformance) tests a
server only over Streamable HTTP (`conformance server --url`). `fathomgate
serve` speaks stdio toward the agent in M0. This relay turns one into the
other so the suite can drive the real `fathomgate serve` binary, stdio
transport included.

It is deliberately dumb. JSON-RPC messages are forwarded byte-for-byte in
meaning, with two exceptions, both listed here and nowhere else:

1. Request ids. Several HTTP requests can share one child process, and the
   suite reuses ids across requests, so the relay gives each forwarded
   request a fresh integer id and puts the client's id back on the
   response, and on the `io.modelcontextprotocol/subscriptionId` tag of a
   notification that names the request. Ids of requests the *child* sends
   (elicitation, sampling) are not touched.
2. `--tool-prefix P`. The suite calls fixed tool names (`test_simple_text`);
   fathomgate exposes every upstream tool as `<server>.<tool>` (profile-schema
   section 8.1). With `--tool-prefix conf`, a `tools/call` whose name has no
   `.` gets `conf.` prepended. Nothing else is renamed: `tools/list` reaches
   the suite with fathomgate's prefixed names, unmodified. The control leg
   (relay straight to the fixture, no fathomgate) runs without a prefix.

Process model, matching how an agent uses a stdio server:

- A POST carrying `initialize` (2025 era) spawns one child for a new session
  and returns its `Mcp-Session-Id`. Later requests with that header go to
  that child; DELETE ends it.
- A POST with no session header and no `initialize` (2026 era, stateless,
  `_meta` on every request) goes to one shared child. It must be one process:
  fathomgate seals `requestState` under a per-process key, so an MRTR retry has
  to reach the process that issued it.

Every POST that carries a request is answered as `text/event-stream`: each
message the child sends while the request is open (progress, logging,
elicitation/create) is written as an event, and the stream closes after the
response. GET is answered 405, which the transport spec allows.

What the relay does NOT prove: anything about HTTP itself. Header
validation, DNS-rebinding protection, SSE resumption and multiple streams
are the relay's behaviour here, not fathomgate's, because fathomgate has no HTTP
listener in M0. `tests/conformance/README.md` lists the scenarios this
affects. The control leg runs the same relay in front of the fixture alone,
so a failure that appears only with fathomgate in the path is fathomgate's.

Standard library only; run with `python3 relay.py --port 3001 -- cmd args`.
"""

from __future__ import annotations

import argparse
import json
import queue
import signal
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SESSION_HEADER = "Mcp-Session-Id"
SUBSCRIPTION_ID = "io.modelcontextprotocol/subscriptionId"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_END = object()  # queued when the child exits, so open streams close


def loopback_host(value: str) -> bool:
    """True if a Host header or Origin URL names a loopback host."""
    host = value.split("://", 1)[-1].split("/", 1)[0].lower()
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    elif host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host in LOOPBACK


def log(msg: str) -> None:
    print(f"relay: {msg}", file=sys.stderr, flush=True)


class Child:
    """One stdio MCP server process and the HTTP streams waiting on it."""

    def __init__(self, argv: list[str], label: str) -> None:
        self.label = label
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: the child's log lines go to our stderr
            bufsize=0,
        )
        self.lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.next_id = 0
        # relay id -> (client id, stream queue)
        self.pending: dict[int, tuple[object, queue.Queue]] = {}
        # progress token -> stream queue, for notifications/progress routing
        self.progress: dict[object, queue.Queue] = {}
        # open streams, oldest first; unrouted child messages go to the oldest
        self.streams: list[queue.Queue] = []
        self.alive = True
        threading.Thread(target=self._read, name=f"read-{label}", daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                log(f"{self.label}: non-JSON line from child dropped ({len(line)} bytes)")
                continue
            self._route(msg)
        with self.lock:
            self.alive = False
            streams = list(self.streams)
        for q in streams:
            q.put(_END)
        log(f"{self.label}: child exited with {self.proc.wait()}")

    def _route(self, msg: dict) -> None:
        is_response = isinstance(msg, dict) and "method" not in msg and "id" in msg
        with self.lock:
            if is_response:
                entry = self.pending.pop(msg["id"], None) if isinstance(msg["id"], int) else None
                if entry is None:
                    log(f"{self.label}: response to unknown id {msg.get('id')!r} dropped")
                    return
                client_id, q = entry
                msg["id"] = client_id
                q.put(("response", client_id, msg))
                # A stream whose requests are all answered takes no more
                # unrouted messages, even before its handler closes it.
                if q in self.streams and not any(pq is q for _, pq in self.pending.values()):
                    self.streams.remove(q)
                return
            params = msg.get("params") if isinstance(msg, dict) else None
            q = None
            if isinstance(params, dict):
                token = params.get("progressToken")
                q = self.progress.get(token) if token is not None else None
                # 2026 listen streams: the child tags each notification with
                # the id of the subscriptions/listen request, which is the
                # relay's id. Route by it and put the client's id back.
                meta = params.get("_meta")
                sub = meta.get(SUBSCRIPTION_ID) if isinstance(meta, dict) else None
                if q is None and isinstance(sub, int) and sub in self.pending:
                    client_id, q = self.pending[sub]
                    meta[SUBSCRIPTION_ID] = client_id
            if q is None and self.streams:
                q = self.streams[0]
        if q is None:
            log(f"{self.label}: {msg.get('method')!r} with no open stream dropped")
            return
        q.put(("message", None, msg))

    def open_stream(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self.lock:
            self.streams.append(q)
            if not self.alive:
                q.put(_END)
        return q

    def close_stream(self, q: queue.Queue) -> None:
        with self.lock:
            if q in self.streams:
                self.streams.remove(q)
            for rid in [r for r, (_, pq) in self.pending.items() if pq is q]:
                del self.pending[rid]
            for tok in [t for t, pq in self.progress.items() if pq is q]:
                del self.progress[tok]

    def register(self, msg: dict, q: queue.Queue) -> None:
        """Rewrite a client request's id and remember where its answer goes."""
        with self.lock:
            self.next_id += 1
            rid = self.next_id
            self.pending[rid] = (msg["id"], q)
            params = msg.get("params")
            meta = params.get("_meta") if isinstance(params, dict) else None
            if isinstance(meta, dict) and "progressToken" in meta:
                self.progress[meta["progressToken"]] = q
        msg["id"] = rid

    def send(self, msg: dict) -> bool:
        data = (json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        with self.write_lock:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
                return True
            except (BrokenPipeError, OSError):
                return False

    def stop(self) -> None:
        if self.proc.poll() is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.close()
                self.proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()
                self.proc.wait()


class Relay:
    def __init__(self, argv: list[str], tool_prefix: str) -> None:
        self.argv = argv
        self.tool_prefix = tool_prefix
        self.lock = threading.Lock()
        self.sessions: dict[str, Child] = {}
        self.shared: Child | None = None

    def new_session(self) -> tuple[str, Child]:
        sid = uuid.uuid4().hex
        child = Child(self.argv, f"session {sid[:8]}")
        with self.lock:
            self.sessions[sid] = child
        return sid, child

    def session(self, sid: str) -> Child | None:
        with self.lock:
            return self.sessions.get(sid)

    def end_session(self, sid: str) -> bool:
        with self.lock:
            child = self.sessions.pop(sid, None)
        if child is None:
            return False
        child.stop()
        return True

    def stateless(self) -> Child:
        with self.lock:
            if self.shared is None or not self.shared.alive:
                self.shared = Child(self.argv, "stateless")
            return self.shared

    def adapt(self, msg: dict) -> None:
        """The tool-name adapter (module docstring, exception 2)."""
        if not self.tool_prefix or msg.get("method") != "tools/call":
            return
        params = msg.get("params")
        if isinstance(params, dict) and isinstance(params.get("name"), str) and "." not in params["name"]:
            params["name"] = f"{self.tool_prefix}.{params['name']}"

    def stop(self) -> None:
        with self.lock:
            children = list(self.sessions.values()) + ([self.shared] if self.shared else [])
            self.sessions.clear()
        for c in children:
            c.stop()


def make_handler(relay: Relay, path: str):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:  # quiet access log
            pass

        def _plain(self, status: int, text: str, headers: dict[str, str] | None = None) -> None:
            body = text.encode()
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            if status >= 400:
                # The request body may be unread; never reuse the connection.
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _path_ok(self) -> bool:
            # DNS-rebinding protection for a loopback listener: refuse a Host
            # or Origin that is not loopback, as go-sdk's handler does.
            origin = self.headers.get("Origin")
            if not loopback_host(self.headers.get("Host", "")) or (origin and not loopback_host(origin)):
                self._plain(403, "forbidden: Host and Origin must be loopback")
                return False
            if self.path.split("?", 1)[0] != path:
                self._plain(404, "not found")
                return False
            return True

        def do_GET(self) -> None:
            if self._path_ok():
                self._plain(405, "method not allowed", {"Allow": "POST, DELETE"})

        def do_DELETE(self) -> None:
            if not self._path_ok():
                return
            sid = self.headers.get(SESSION_HEADER)
            if not sid:
                self._plain(400, f"DELETE needs {SESSION_HEADER}")
            elif relay.end_session(sid):
                self._plain(200, "")
            else:
                self._plain(404, "unknown session")

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            if not self._path_ok():
                return
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                self._plain(400, "body is not JSON")
                return
            msgs = body if isinstance(body, list) else [body]
            if not msgs or not all(isinstance(m, dict) for m in msgs):
                self._plain(400, "body is not a JSON-RPC message")
                return

            headers: dict[str, str] = {}
            sid = self.headers.get(SESSION_HEADER)
            if sid:
                child = relay.session(sid)
                if child is None:
                    self._plain(404, "unknown session")
                    return
            elif any(m.get("method") == "initialize" for m in msgs):
                sid, child = relay.new_session()
                headers[SESSION_HEADER] = sid
            else:
                child = relay.stateless()

            requests = [m for m in msgs if "method" in m and "id" in m]
            if not requests:
                for m in msgs:
                    child.send(m)
                self._plain(202, "", headers)
                return

            q = child.open_stream()
            waiting = set()
            try:
                for m in requests:
                    relay.adapt(m)
                    waiting.add(json.dumps(m["id"]))
                    child.register(m, q)
                for m in msgs:
                    if not child.send(m):
                        self._plain(502, "upstream process is not running", headers)
                        return
                self.send_response(200)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                while waiting:
                    item = q.get()
                    if item is _END:
                        break
                    kind, client_id, msg = item
                    data = json.dumps(msg, separators=(",", ":"), ensure_ascii=False)
                    self.wfile.write(f"event: message\ndata: {data}\n\n".encode())
                    self.wfile.flush()
                    if kind == "response":
                        waiting.discard(json.dumps(client_id))
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                child.close_stream(q)

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--path", default="/mcp")
    ap.add_argument("--tool-prefix", default="", help="prepend '<P>.' to unprefixed tools/call names")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="-- stdio server command and arguments")
    args = ap.parse_args(argv)
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        ap.error("missing server command after --")

    relay = Relay(cmd, args.tool_prefix)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(relay, args.path))
    server.daemon_threads = True

    def shutdown(*_: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    log(f"listening on http://{args.host}:{args.port}{args.path} -> {' '.join(cmd)}")
    try:
        server.serve_forever()
    finally:
        relay.stop()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
