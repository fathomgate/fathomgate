# SPDX-License-Identifier: Apache-2.0
"""Auth-and-prefix shim between the conformance suite and an HTTP MCP server.

The official MCP conformance suite (@modelcontextprotocol/conformance) drives
a server over Streamable HTTP (`conformance server --url`). It has no option
to send an `Authorization` header and it calls fixed tool names
(`test_simple_text`), while `fathomgate serve --listen` requires a bearer
token on every request and exposes each upstream tool as `<server>.<tool>`
(profile-schema section 8.1). This shim sits between the two (ADR 0016,
*Testing*, T0.32). It is a reverse proxy that makes exactly two changes,
listed here and nowhere else:

1. Token. When CONFORMANCE_SHIM_TOKEN is set in its environment, every
   request gets `Authorization: Bearer <token>`, replacing any the suite
   sent. The token is read from the environment only (never argv, so it is
   not in the process list) and never logged.
2. `--tool-prefix P`. A request whose `Mcp-Method` header is `tools/call`
   gets `P.` in front of an `Mcp-Name` value that has no `.`; a JSON-RPC
   request body whose `method` is `tools/call` gets `P.` in front of a
   `params.name` that has no `.`. The two are rewritten separately, by the
   same rule, so a deliberate header/body mismatch stays a mismatch
   (`a` vs `b` becomes `P.a` vs `P.b`). A body is re-serialised only when
   its name changes; every other body is forwarded as the bytes that
   arrived. An `Mcp-Name` in `=?base64?...?=` form is left alone.

Everything else passes through: method, path and query, status, reason,
headers (hop-by-hop headers aside, as for any HTTP/1.1 proxy; `Host` as the
suite sent it; a rewritten body gets its new `Content-Length`), session ids, and
the response body, streamed chunk by chunk as it arrives so SSE events and a
long-lived GET stream reach the suite when the server sends them. The shim
keeps no sessions, does not renumber ids, and does not touch `tools/list` or
any response: the suite sees the server's own prefixed names.

Without `--tool-prefix` and without a token (the control legs) it changes
nothing, so a control leg run through it proves it transparent.

  CONFORMANCE_SHIM_TOKEN=... python3 shim.py --target http://127.0.0.1:P/mcp --tool-prefix conf

It binds 127.0.0.1 on a free port (or `--port`) and prints one line,
`shim listening url=http://127.0.0.1:<port>/mcp`, on stdout. Standard
library only. Remove it when the suite can send a header and map tool names
(the upstream requests drafted in the T0.32 handoff).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import select
import socket
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN_ENV = "CONFORMANCE_SHIM_TOKEN"

# RFC 9110 section 7.6.1 connection-specific headers, plus Content-Length,
# which the shim sets from the body it sends. Host is not here: it passes
# through as the suite sent it, so the suite's DNS-rebinding probe
# (`Host: evil.example.com`) reaches the server unchanged.
HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)


def prefixed(name: str, prefix: str) -> str | None:
    """The name with `prefix.` in front, or None when it is left alone."""
    if not prefix or "." in name or (name.startswith("=?") and name.endswith("?=")):
        return None
    return f"{prefix}.{name}"


def rewrite_body(body: bytes, prefix: str) -> bytes:
    """Prefix params.name of a single tools/call request; else the same bytes."""
    if not prefix or not body:
        return body
    try:
        msg = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        return body
    params = msg.get("params")
    if not isinstance(params, dict) or not isinstance(params.get("name"), str):
        return body
    new = prefixed(params["name"], prefix)
    if new is None:
        return body
    params["name"] = new
    return json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode()


def rewrite_headers(headers: list[tuple[str, str]], prefix: str, token: str) -> list[tuple[str, str]]:
    """Request headers to send upstream: hop-by-hop dropped, Mcp-Name
    prefixed on a tools/call, Authorization set when there is a token."""
    tools_call = any(k.lower() == "mcp-method" and v == "tools/call" for k, v in headers)
    out: list[tuple[str, str]] = []
    for k, v in headers:
        low = k.lower()
        if low in HOP_BY_HOP or (token and low == "authorization"):
            continue
        if low == "mcp-name" and tools_call:
            v = prefixed(v, prefix) or v
        out.append((k, v))
    if token:
        out.append(("Authorization", f"Bearer {token}"))
    return out


def make_handler(target: str, prefix: str, token: str):
    u = urllib.parse.urlsplit(target)
    if u.scheme != "http" or not u.hostname or not u.port:
        raise ValueError("--target must be http://<host>:<port>/<path>")
    host, port = u.hostname, u.port

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args) -> None:  # noqa: A002 - base class name
            # Request line and status only; headers (the token) are never logged.
            sys.stderr.write("shim: " + (format % args) + "\n")
            sys.stderr.flush()

        def handle(self) -> None:
            try:
                super().handle()
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass  # the suite closed its connection; there is no one to answer

        def _read_body(self) -> bytes:
            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                    if size == 0:
                        while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                            pass
                        return b"".join(chunks)
                    chunks.append(self.rfile.read(size))
                    self.rfile.readline()
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _forward(self) -> None:
            body = self._read_body()
            has_body = body or self.headers.get("Content-Length") is not None
            body = rewrite_body(body, prefix)
            headers = rewrite_headers(list(self.headers.items()), prefix, token)
            conn = http.client.HTTPConnection(host, port, timeout=None)
            try:
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                for k, v in headers:
                    conn.putheader(k, v)
                if has_body or self.command == "POST":
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(body if body else None)
                # Kept here: http.client drops conn.sock once a response
                # says `Connection: close`, and the watcher needs it.
                upstream = conn.sock
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                conn.close()
                self.send_error(502, f"shim: target unreachable: {e.__class__.__name__}")
                return
            try:
                self._relay(resp, upstream)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                self.close_connection = True
            finally:
                conn.close()

        def _watch_client(self, upstream: socket.socket, done: threading.Event) -> None:
            """While a streamed response is open, close the upstream side as
            soon as the suite closes its side, so the server sees the stream
            end when the client ends it (a GET stream, an aborted POST)."""
            while not done.is_set():
                readable, _, _ = select.select([self.connection], [], [], 0.2)
                if not readable:
                    continue
                try:
                    data = self.connection.recv(1, socket.MSG_PEEK)
                except OSError:
                    data = b""
                if not data:
                    try:
                        upstream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                return  # EOF handled, or a pipelined request: stop watching

        def _relay(self, resp: http.client.HTTPResponse, upstream: socket.socket) -> None:
            self.log_request(resp.status)
            self.send_response_only(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in HOP_BY_HOP:
                    self.send_header(k, v)
            bodyless = self.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
            if bodyless:
                self.end_headers()
                return
            if resp.length is not None and not resp.chunked:
                self.send_header("Content-Length", str(resp.length))
                self.end_headers()
                self.wfile.write(resp.read())
                self.wfile.flush()
                return
            # Unknown length (SSE, chunked): re-chunk as it arrives.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.flush()
            done = threading.Event()
            threading.Thread(target=self._watch_client, args=(upstream, done), daemon=True).start()
            try:
                while True:
                    try:
                        chunk = resp.read1(65536)
                    except (OSError, http.client.HTTPException):
                        # The stream broke, or the suite left and the watcher
                        # shut the upstream side: end without the last chunk,
                        # so a cut stream reads as cut, not as complete.
                        self.close_connection = True
                        return
                    if not chunk:
                        break
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            finally:
                done.set()

        do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_OPTIONS = do_HEAD = _forward

    return Handler


def serve(target: str, prefix: str, token: str, port: int = 0) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(target, prefix, token))
    httpd.daemon_threads = True
    return httpd


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--target", required=True, help="the server's URL, http://127.0.0.1:<port>/mcp")
    ap.add_argument("--tool-prefix", default="", help="prefix for unprefixed tools/call names (fathomgate legs: conf)")
    ap.add_argument("--port", type=int, default=0, help="port to bind on 127.0.0.1 (default: a free one)")
    args = ap.parse_args(argv)
    token = os.environ.get(TOKEN_ENV, "")
    httpd = serve(args.target, args.tool_prefix, token, args.port)
    path = urllib.parse.urlsplit(args.target).path or "/"
    print(f"shim listening url=http://127.0.0.1:{httpd.server_address[1]}{path}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
