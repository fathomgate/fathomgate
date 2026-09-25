# SPDX-License-Identifier: FSL-1.1-ALv2
"""Fake Arista eAPI device: an HTTPS JSON-RPC endpoint (`POST /command-api`,
method `runCmds`) that answers from canned FAKE transcripts, so tier 2 can run
the real shigechika/eos-mcp (pyeapi over HTTPS) without a real switch (M1-22).

    FAKE_EAPI_PASSWORD=... python fake_eapi.py --state-dir DIR [--host 127.0.0.1] [--port 443]

The server is the standard library only (http.server, ssl, json). The one
thing the standard library cannot do is make a certificate, so the throwaway
self-signed certificate and its key are generated at start with
`cryptography` (already in the tests' `integration` extra through asyncssh)
and written to DIR, never to the repository. eos-mcp 1.3.0 hands pyeapi 1.0.4
an unverified TLS context whatever its config says (see the README), so the
certificate only has to exist.

Why port 443: eos-mcp passes no port to `pyeapi.connect`, and pyeapi's HTTPS
transport then uses 443 (eapilib.py DEFAULT_HTTPS_PORT). The host part comes
from the tool's `hostname` argument. So a fake device eos-mcp can reach has to
listen on 443. On Linux that needs `sysctl net.ipv4.ip_unprivileged_port_start=443`
(the CI job sets it) or root; Windows and macOS let any user bind it. If the
bind fails, the process prints `BIND-FAILED <errno> <message>` and exits 3.

It prints `READY <port>` on stdout once it accepts connections. What it
records, in DIR:

- connections.log: one line per TCP connection, written at accept, before the
  TLS handshake and before authentication: `<peer-ip>`. Then, when the
  handshake completes, one line `tls <sni-or-->` (pyeapi sends the hostname
  it was given as SNI; an IP address sends none). A test that sees no new
  line here knows eos-mcp never connected.
- requests.log: one JSON object per runCmds request, as received:
  `{"user", "cmds", "format", "version"}`. It shows which commands travelled
  together in one eAPI call (push_config sends its whole session in one).
- commands.log: one line per command in every authenticated request,
  `<user>\t<command>`, in the format fake_ssh.py uses, so the conftest's
  FakeDevice.commands() reads both.

Answers. Basic auth against --username (default `admin`) and
FAKE_EAPI_PASSWORD (default `FAKE-eapi-pass`); a wrong pair gets HTTP 401
and is logged in connections.log as `auth-failed <user>`, never in the
command logs. Each command in `cmds` (a string, or `{"cmd": ..., "input":
...}`) is looked up the way fake_ssh.py does: `format: text` reads
transcripts/eos/<name>.txt and answers `{"output": <text>}`; `format: json`
reads transcripts/eos/eapi/<name>.json. The first command with no transcript
stops the request with eAPI's error shape (code 1002, `CLI command <i> of <n>
'<cmd>' failed: invalid command`, `data` holding the results so far and
`{"errors": ["Invalid input"]}` for the failing command), which is what real
EOS does with an unknown command: the rest of the list does not run.

A sketch of EOS configure sessions, enough for eos-mcp's session tools to get
well-formed answers, and no more: `configure session <name>` enters the
session; every line after it answers `{}` and is recorded against the session
until `show session-config diffs` (answers the recorded lines, each prefixed
with `+`), `abort`, `commit`, `commit timer hh:mm:ss`, or `end`. `end` leaves
the session pending and returns to exec mode, so a following `reload now` is
looked up as an exec command (no transcript: invalid command). None of this
is EOS's behaviour; it is not evidence for any device-side claim. The README
lists what only cEOS can prove (M1-28).

Every value here is a fixture. Never point an MCP server with real
credentials at this, and never point this at a real network.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import http.server
import json
import os
import re
import socket
import ssl
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_PASSWORD = "FAKE-eapi-pass"

_NO_MORE = re.compile(r"\s*\|\s*no-more\s*$", re.I)
_SESSION = re.compile(r"^configure session (\S+)$")
_SESSION_END = re.compile(r"^configure session (\S+) (commit|abort)$")
_COMMIT_TIMER = re.compile(r"^commit timer (\d{2}):(\d{2}):(\d{2})$")


def transcript_name(command: str) -> str:
    """The same mapping as fake_ssh.transcript_name."""
    command = _NO_MORE.sub("", command.strip())
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


def make_certificate(state: Path) -> tuple[Path, Path]:
    """A throwaway self-signed certificate for CN=fake-eos, valid one day."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fake-eos")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = state / "fake-eapi.crt", state / "fake-eapi.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_path, key_path


class Device:
    """Transcripts, session state and the three logs. One lock: requests from
    eos-mcp's batch tools may arrive on several threads."""

    def __init__(self, vendor: str, state: Path, username: str, password: str) -> None:
        self.text_dir = HERE / "transcripts" / vendor
        self.json_dir = self.text_dir / "eapi"
        self.state = state
        self.username = username
        self.password = password
        self.lock = threading.Lock()
        self.pending: dict[str, list[str]] = {}  # committed with a timer, not confirmed
        for name in ("connections.log", "requests.log", "commands.log"):
            (state / name).touch()

    def log(self, name: str, line: str) -> None:
        with self.lock, open(self.state / name, "a", encoding="utf-8", newline="\n") as f:
            f.write(line + "\n")

    def run(self, user: str, cmds: list, fmt: str, version) -> dict:
        commands = [c.get("cmd", "") if isinstance(c, dict) else str(c) for c in cmds]
        self.log("requests.log", json.dumps({"user": user, "cmds": commands, "format": fmt, "version": version}))
        for c in commands:
            self.log("commands.log", f"{user}\t{c}")
        results: list = []
        session: str | None = None
        lines: list[str] = []
        for i, command in enumerate(commands, 1):
            answer = self._one(command, fmt, session, lines)
            if answer is None:
                return {
                    "error": {
                        "code": 1002,
                        "message": f"CLI command {i} of {len(commands)} '{command}' failed: invalid command",
                        "data": results + [{"errors": ["Invalid input"]}],
                    }
                }
            kind, value = answer
            if kind == "enter":
                session, lines = value, []
                results.append({})
            elif kind == "leave":
                session = None
                results.append({})
            else:
                results.append(value)
        return {"result": results}

    def _one(self, command: str, fmt: str, session: str | None, lines: list[str]):
        c = command.strip()
        if m := _SESSION_END.match(c):
            with self.lock:
                self.pending.pop(m.group(1), None)
            return ("value", {})
        if m := _SESSION.match(c):
            return ("enter", m.group(1))
        if session is not None:
            if c == "show session-config diffs":
                return ("value", {"output": "".join(f"+{line}\n" for line in lines)} if fmt == "text" else {})
            if c in ("abort", "commit"):
                return ("leave", None)
            if m := _COMMIT_TIMER.match(c):
                with self.lock:
                    self.pending[session] = list(lines)
                return ("leave", None)
            if c == "end":
                with self.lock:
                    self.pending.setdefault(session, list(lines))
                return ("leave", None)
            lines.append(c)
            return ("value", {})
        if c == "show configuration sessions detail" and fmt == "text":
            with self.lock:
                names = sorted(self.pending)
            body = "".join(f"  {n:<20} pending\n" for n in names) or "  (none)\n"
            return ("value", {"output": "Name                 State\n" + body})
        name = transcript_name(c)
        if fmt == "json":
            path = self.json_dir / f"{name}.json"
            return ("value", json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else None
        path = self.text_dir / f"{name}.txt"
        return ("value", {"output": path.read_text(encoding="utf-8")}) if path.is_file() else None


class Handler(http.server.BaseHTTPRequestHandler):
    server: "Server"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - http.server's name
        pass  # stdout carries only the READY line

    def _reply(self, status: int, body: dict | None, extra: dict[str, str] | None = None) -> None:
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _user(self) -> str | None:
        device = self.server.device
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return None
        try:
            user, _, password = base64.b64decode(auth[6:]).decode().partition(":")
        except ValueError:
            return None
        if user == device.username and password == device.password:
            return user
        device.log("connections.log", f"auth-failed {user}")
        return None

    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        device = self.server.device
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        if self.path != "/command-api":
            self._reply(404, {"error": "not found"})
            return
        user = self._user()
        if user is None:
            self._reply(401, {"error": "Unable to authenticate user: Bad username/password combination"}, {"WWW-Authenticate": 'Basic realm="eAPI"'})
            return
        try:
            req = json.loads(raw)
            params = req["params"]
            cmds = params["cmds"]
            if req.get("method") != "runCmds" or not isinstance(cmds, list):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            self._reply(200, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request"}})
            return
        out = device.run(user, cmds, params.get("format") or "json", params.get("version"))
        self._reply(200, {"jsonrpc": "2.0", "id": req.get("id"), **out})

    def do_GET(self) -> None:  # noqa: N802
        self._reply(405, {"error": "use POST /command-api"})


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # never share 443 with another listener

    def __init__(self, addr: tuple[str, int], device: Device, context: ssl.SSLContext) -> None:
        self.device = device
        self.context = context
        super().__init__(addr, Handler)

    def finish_request(self, request: socket.socket, client_address) -> None:
        # Logged at accept, on the request thread, before TLS and before auth.
        self.device.log("connections.log", str(client_address[0]))
        request.settimeout(30)
        try:
            tls = self.context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as e:
            self.device.log("connections.log", f"tls-failed {type(e).__name__}")
            return
        sni = getattr(tls, "_fake_sni", None) or "-"
        self.device.log("connections.log", f"tls {sni}")
        self.RequestHandlerClass(tls, client_address, self)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--vendor", default="eos")
    ap.add_argument("--state-dir", required=True, type=Path)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--username", default="admin")
    args = ap.parse_args()

    state = args.state_dir
    state.mkdir(parents=True, exist_ok=True)
    device = Device(args.vendor, state, args.username, os.environ.get("FAKE_EAPI_PASSWORD", DEFAULT_PASSWORD))
    cert, key = make_certificate(state)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    def sni(sock: ssl.SSLObject, name: str | None, _ctx: ssl.SSLContext) -> None:
        sock._fake_sni = name  # read back in finish_request

    ctx.sni_callback = sni
    try:
        server = Server((args.host, args.port), device, ctx)
    except OSError as e:
        print(f"BIND-FAILED {e.errno} {e.strerror}", flush=True)
        sys.exit(3)
    print(f"READY {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
