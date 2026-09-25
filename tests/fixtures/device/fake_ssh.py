# SPDX-License-Identifier: FSL-1.1-ALv2
"""Fake network device: an asyncssh server that answers `show` commands from
canned transcripts, so tier 2 can run a real upstream MCP server without a
real device.

Two ways in:

- The SSH *exec* channel (T0.5), which is what krisiasty/netdev-ssh-mcp
  v1.6.6 and v1.7.1 use: one non-PTY `session.Output(cmd)` per call, see
  internal/sshclient/client.go (unchanged between those tags).
- An interactive shell (T0.34), which is what netmiko uses (upa/
  mcp-netmiko-server, `device_type = "arista_eos"`): a PTY, the prompt
  `<hostname>#`, input echoed, one command per line, the prompt again after
  every answer. `terminal width <n>` and `terminal length 0` answer the way
  EOS does (`Width set to <n> columns.`, `Pagination disabled.`), because
  netmiko's EOS session preparation waits for those words; `exit` or `quit`
  closes the session; an empty line prints the prompt again.

There is no config mode and no commit/rollback state yet; those arrive with
the change-safety drivers (M3) and their transcripts from the Network Safety
Engineer.

    python fake_ssh.py --vendor eos --state-dir DIR

It generates an ed25519 host key in DIR, listens on 127.0.0.1 (port 0 means
pick one), writes DIR/known_hosts with the key for `[127.0.0.1]:<port>`, and
prints one line `READY <port>` on stdout once it accepts connections. Every
exec request, and every non-empty line typed at the shell prompt, is
appended to DIR/commands.log as `<user>\t<command>`, so a test can prove
what reached the device (or that nothing did). Every SSH connection, before
authentication, appends one line to DIR/sessions.log, so a test can prove
that a denied call opened no session at all.

Auth is password only: the username and password come from --username and
the FAKE_DEVICE_PASSWORD environment variable (default `FAKE-device-pass`).
Both are fixtures; never point this at anything real.

A command maps to transcripts/<vendor>/<name>.txt where <name> is the
command lower-cased with runs of non-alphanumerics replaced by `_`
(`show version` -> `show_version.txt`); a trailing `| no-more` is dropped
first (`show running-config | no-more` -> `show_running_config.txt`). An
unknown command writes an EOS-style `% Invalid input` (to stderr with exit
status 1 on the exec channel, to the terminal at the shell).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

import asyncssh

HERE = Path(__file__).resolve().parent
DEFAULT_PASSWORD = "FAKE-device-pass"


# `| no-more` only turns paging off; the device prints the same text. The
# upstream's get_config appends it (`show running-config | no-more` for EOS),
# so it is dropped before the lookup. Other pipes (`| include`, `| json`)
# change the output and stay part of the name. commands.log keeps the
# command exactly as sent.
_NO_MORE = re.compile(r"\s*\|\s*no-more\s*$", re.I)


def transcript_name(command: str) -> str:
    command = _NO_MORE.sub("", command.strip())
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


class _Server(asyncssh.SSHServer):
    def __init__(self, username: str, password: str, sessions: Path) -> None:
        self._username = username
        self._password = password
        self._sessions = sessions

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        with self._sessions.open("a", encoding="utf-8") as f:
            f.write("connect\n")

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == self._username and password == self._password


# EOS answers to the terminal settings netmiko's arista_eos session
# preparation sends (netmiko/arista/arista.py: it waits for "Width set to"
# and "Pagination disabled").
_TERMINAL_WIDTH = re.compile(r"^terminal\s+width\s+(\d+)$", re.I)
_TERMINAL_LENGTH_0 = re.compile(r"^terminal\s+length\s+0$", re.I)


def _log(log: Path, user: str, command: str) -> None:
    with log.open("a", encoding="utf-8") as f:
        f.write(f"{user}\t{command}\n")


def shell_answer(transcripts: Path, line: str) -> str:
    """What the shell prints for one command line, before the next prompt."""
    if m := _TERMINAL_WIDTH.match(line):
        return f"Width set to {m.group(1)} columns.\n"
    if _TERMINAL_LENGTH_0.match(line):
        return "Pagination disabled.\n"
    path = transcripts / f"{transcript_name(line)}.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return "% Invalid input\n"


async def _shell(process: asyncssh.SSHServerProcess, transcripts: Path, log: Path, user: str, hostname: str) -> None:
    prompt = f"{hostname}#"
    process.stdout.write(prompt)
    while True:
        try:
            raw = await process.stdin.readline()
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
            continue
        if not raw:  # EOF
            break
        line = raw.strip()
        if not line:
            process.stdout.write(prompt)
            continue
        _log(log, user, line)
        if line.lower() in ("exit", "quit"):
            break
        process.stdout.write(shell_answer(transcripts, line))
        process.stdout.write(prompt)
    process.exit(0)


def _make_handler(transcripts: Path, log: Path, hostname: str):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        user = process.get_extra_info("username") or ""
        if process.command is None:
            await _shell(process, transcripts, log, user, hostname)
            return
        command = process.command
        _log(log, user, command)
        path = transcripts / f"{transcript_name(command)}.txt"
        if path.is_file():
            process.stdout.write(path.read_text(encoding="utf-8"))
            process.exit(0)
        else:
            process.stderr.write("% Invalid input\n")
            process.exit(1)

    return handle


async def serve(vendor: str, state_dir: Path, port: int, username: str, password: str, hostname: str = "fake-eos") -> None:
    transcripts = HERE / "transcripts" / vendor
    if not transcripts.is_dir():
        raise SystemExit(f"fake device: no transcripts for vendor {vendor!r} in {transcripts}")
    state_dir.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = state_dir / "host_key"
    key.write_private_key(str(key_path))
    log = state_dir / "commands.log"
    log.touch()
    sessions = state_dir / "sessions.log"
    sessions.touch()

    acceptor = await asyncssh.create_server(
        lambda: _Server(username, password, sessions),
        "127.0.0.1",
        port,
        server_host_keys=[str(key_path)],
        process_factory=_make_handler(transcripts, log, hostname),
        encoding="utf-8",
    )
    bound = acceptor.sockets[0].getsockname()[1]
    pub = key.export_public_key("openssh").decode().strip()
    (state_dir / "known_hosts").write_text(f"[127.0.0.1]:{bound} {pub}\n", encoding="utf-8")
    print(f"READY {bound}", flush=True)
    await acceptor.wait_closed()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vendor", default="eos")
    ap.add_argument("--state-dir", type=Path, required=True)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--username", default="admin")
    ap.add_argument("--hostname", default="fake-eos", help="shell prompt name (the prompt is <hostname>#)")
    args = ap.parse_args(argv)
    password = os.environ.get("FAKE_DEVICE_PASSWORD", DEFAULT_PASSWORD)
    try:
        asyncio.run(serve(args.vendor, args.state_dir, args.port, args.username, password, args.hostname))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
